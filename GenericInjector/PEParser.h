#pragma once
#include "InjectedFunction.h"
#include "Misc.h"
#include <unordered_map>

class PEPaser final
{
public:
	explicit PEPaser(const byte* pPEData);
	~PEPaser() = default;

	bool DllImported(tstring const& DllName) const noexcept;

	LPDWORD GetImportFunctionAddress(tstring const& DllName, tstring const& Funcname) const noexcept;
	LPDWORD GetImportFunctionAddress(tstring const& DllName, DWORD Index) const noexcept;

	IMAGE_DOS_HEADER const& GetDosHeader() const;
	IMAGE_NT_HEADERS const& GetNTHeaders() const;
	std::vector<IMAGE_SECTION_HEADER> const& GetSections() const;

private:
	bool m_Inited;
	IMAGE_DOS_HEADER m_DosHeader;
	IMAGE_NT_HEADERS m_NTHeader;
	std::vector<IMAGE_SECTION_HEADER> m_Sections;
	std::unordered_map<tstring, std::pair<std::unordered_map<tstring, LPDWORD>, std::unordered_map<DWORD, LPDWORD>>, std::hash<tstring>, CaseIgnoredStringEqualTo<TCHAR>> m_ImportTable;

	void init(const byte* pPEData);
};