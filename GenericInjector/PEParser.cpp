#include "PEParser.h"

PEPaser::PEPaser(const byte* pPEData)
{
	if (pPEData == nullptr)
	{
		throw std::invalid_argument("pPEData can not be a nullptr.");
	}

	init(pPEData);
}

bool PEPaser::DllImported(tstring const & DllName) const noexcept
{
	return m_ImportTable.find(DllName) != m_ImportTable.end();
}

LPDWORD PEPaser::GetImportFunctionAddress(tstring const & DllName, tstring const & Funcname) const noexcept
{
	auto tItea = m_ImportTable.find(DllName);
	if (tItea == m_ImportTable.end())
	{
		return nullptr;
	}

	auto tFuncItea = tItea->second.first.find(Funcname);
	return tFuncItea == tItea->second.first.end() ? nullptr : tFuncItea->second;
}

LPDWORD PEPaser::GetImportFunctionAddress(tstring const & DllName, DWORD Index) const noexcept
{
	auto tItea = m_ImportTable.find(DllName);
	if (tItea == m_ImportTable.end())
	{
		return nullptr;
	}

	auto tFuncItea = tItea->second.second.find(Index);
	return tFuncItea == tItea->second.second.end() ? nullptr : tFuncItea->second;
}

void PEPaser::init(const byte* pPEData)
{
	const byte* pCurrentPointer = pPEData;
	IMAGE_DOS_HEADER DosHeader;
	memcpy_s(&DosHeader, sizeof(IMAGE_DOS_HEADER), pCurrentPointer, sizeof(IMAGE_DOS_HEADER));
	pCurrentPointer = pPEData + DosHeader.e_lfanew;
	IMAGE_NT_HEADERS NTHeader;
	memcpy_s(&NTHeader, sizeof(IMAGE_NT_HEADERS), pCurrentPointer, sizeof(IMAGE_NT_HEADERS));
	pCurrentPointer += sizeof(IMAGE_NT_HEADERS);
	std::vector<IMAGE_SECTION_HEADER> sections(NTHeader.FileHeader.NumberOfSections);
	memcpy_s(sections.data(), sections.size() * sizeof(IMAGE_SECTION_HEADER), pCurrentPointer, sections.size() * sizeof(IMAGE_SECTION_HEADER));
	pCurrentPointer += sections.size() * sizeof(IMAGE_SECTION_HEADER);
	std::vector<IMAGE_IMPORT_DESCRIPTOR> ImportTable(NTHeader.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));

	for (auto itea = sections.rbegin(); itea != sections.rend(); ++itea)
	{
		if (itea->VirtualAddress <= NTHeader.OptionalHeader.DataDirectory[1].VirtualAddress)
		{
			memcpy_s(ImportTable.data(), ImportTable.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR), NTHeader.OptionalHeader.DataDirectory[1].VirtualAddress + pPEData, ImportTable.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR));
			for (auto const& i : ImportTable)
			{
				if (i.FirstThunk != 0ul)
				{
					auto& FunctionInfo = m_ImportTable[GetTString(std::string(reinterpret_cast<const char*>(pPEData + i.Name)))];

					pCurrentPointer = i.OriginalFirstThunk + pPEData;
					for (uint iFunc = 0u; ; ++iFunc)
					{
						IMAGE_THUNK_DATA FuncThunkData;
						memcpy_s(&FuncThunkData, sizeof(IMAGE_THUNK_DATA), pCurrentPointer, sizeof(IMAGE_THUNK_DATA));
						pCurrentPointer += sizeof(IMAGE_THUNK_DATA);
						if (FuncThunkData.u1.Ordinal == 0ul)
						{
							break;
						}

						if (FuncThunkData.u1.Ordinal & IMAGE_ORDINAL_FLAG)
						{
							FunctionInfo.second[FuncThunkData.u1.Ordinal & ~IMAGE_ORDINAL_FLAG] = const_cast<LPDWORD>(reinterpret_cast<const DWORD*>(pPEData + i.FirstThunk + iFunc * sizeof(IMAGE_THUNK_DATA)));
						}
						else
						{
							// ignore hint
							FunctionInfo.first[GetTString(std::string(reinterpret_cast<const char*>(pPEData + FuncThunkData.u1.Function + sizeof(WORD))))] = const_cast<LPDWORD>(reinterpret_cast<const DWORD*>(pPEData + i.FirstThunk + iFunc * sizeof(IMAGE_THUNK_DATA)));
						}
					}
				}
			}

			break;
		}
	}
}
