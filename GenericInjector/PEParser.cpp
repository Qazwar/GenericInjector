#include "PEParser.h"

PEPaser::PEPaser(const byte* pPEData)
	: m_Inited(false)
{
	if (pPEData == nullptr)
	{
		throw std::invalid_argument("pPEData can not be a nullptr.");
	}

	init(pPEData);
}

bool PEPaser::DllImported(tstring const& DllName) const noexcept
{
	return m_Inited ? m_ImportTable.find(DllName) != m_ImportTable.end() : false;
}

LPDWORD PEPaser::GetImportFunctionAddress(tstring const& DllName, tstring const& Funcname) const noexcept
{
	if (!m_Inited)
	{
		return nullptr;
	}

	auto tItea = m_ImportTable.find(DllName);
	if (tItea == m_ImportTable.end())
	{
		return nullptr;
	}

	auto tFuncItea = tItea->second.first.find(Funcname);
	return tFuncItea == tItea->second.first.end() ? nullptr : tFuncItea->second;
}

LPDWORD PEPaser::GetImportFunctionAddress(tstring const& DllName, DWORD Index) const noexcept
{
	if (!m_Inited)
	{
		return nullptr;
	}

	auto tItea = m_ImportTable.find(DllName);
	if (tItea == m_ImportTable.end())
	{
		return nullptr;
	}

	auto tFuncItea = tItea->second.second.find(Index);
	return tFuncItea == tItea->second.second.end() ? nullptr : tFuncItea->second;
}

IMAGE_DOS_HEADER const& PEPaser::GetDosHeader() const
{
	if (!m_Inited)
	{
		throw std::runtime_error("Not initialized.");
	}

	return m_DosHeader;
}

IMAGE_NT_HEADERS const& PEPaser::GetNTHeaders() const
{
	if (!m_Inited)
	{
		throw std::runtime_error("Not initialized.");
	}

	return m_NTHeader;
}

void PEPaser::init(const byte* pPEData)
{
	m_Sections.clear();
	m_ImportTable.clear();
	auto pCurrentPointer = pPEData;

	if (IsBadReadPtr(pCurrentPointer, sizeof(IMAGE_DOS_HEADER)))
	{
		throw std::invalid_argument("Pointer not readable.");
	}
	memcpy_s(&m_DosHeader, sizeof(IMAGE_DOS_HEADER), pCurrentPointer, sizeof(IMAGE_DOS_HEADER));
	if (m_DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		throw std::invalid_argument("Not a valid pe header.");
	}

	pCurrentPointer = pPEData + m_DosHeader.e_lfanew;
	if (IsBadReadPtr(pCurrentPointer, sizeof(IMAGE_NT_HEADERS)))
	{
		throw std::invalid_argument("Pointer not readable.");
	}
	memcpy_s(&m_NTHeader, sizeof(IMAGE_NT_HEADERS), pCurrentPointer, sizeof(IMAGE_NT_HEADERS));
	if (m_NTHeader.Signature != IMAGE_NT_SIGNATURE)
	{
		throw std::invalid_argument("Not a valid pe header.");
	}

	pCurrentPointer += sizeof(IMAGE_NT_HEADERS);
	m_Sections.resize(m_NTHeader.FileHeader.NumberOfSections);
	if (IsBadReadPtr(pCurrentPointer, m_Sections.size() * sizeof(IMAGE_SECTION_HEADER)))
	{
		throw std::invalid_argument("Pointer not readable.");
	}
	memcpy_s(m_Sections.data(), m_Sections.size() * sizeof(IMAGE_SECTION_HEADER), pCurrentPointer, m_Sections.size() * sizeof(IMAGE_SECTION_HEADER));
	pCurrentPointer += m_Sections.size() * sizeof(IMAGE_SECTION_HEADER);
	std::vector<IMAGE_IMPORT_DESCRIPTOR> ImportTable(m_NTHeader.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));

	for (auto itea = m_Sections.rbegin(); itea != m_Sections.rend(); ++itea)
	{
		if (itea->VirtualAddress <= m_NTHeader.OptionalHeader.DataDirectory[1].VirtualAddress)
		{
			if (IsBadReadPtr(m_NTHeader.OptionalHeader.DataDirectory[1].VirtualAddress + pPEData, ImportTable.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR)))
			{
				throw std::invalid_argument("Pointer not readable.");
			}
			memcpy_s(ImportTable.data(), ImportTable.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR), m_NTHeader.OptionalHeader.DataDirectory[1].VirtualAddress + pPEData, ImportTable.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR));
			for (auto const& i : ImportTable)
			{
				if (i.FirstThunk != 0ul)
				{
					auto& FunctionInfo = m_ImportTable[GetTString(std::string(reinterpret_cast<const char*>(pPEData + i.Name)))];

					pCurrentPointer = i.OriginalFirstThunk + pPEData;
					for (uint iFunc = 0u; ; ++iFunc)
					{
						IMAGE_THUNK_DATA FuncThunkData;
						if (IsBadReadPtr(pCurrentPointer, sizeof(IMAGE_THUNK_DATA)))
						{
							throw std::invalid_argument("Pointer not readable.");
						}
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

	m_Inited = true;
}
