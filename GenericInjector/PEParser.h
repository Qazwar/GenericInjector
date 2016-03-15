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

private:
	std::unordered_map<tstring, std::pair<std::unordered_map<tstring, LPDWORD>, std::unordered_map<DWORD, LPDWORD>>, std::hash<tstring>, CaseIgnoredStringEqualTo<TCHAR>> m_ImportTable;

	void init(const byte* pPEData);
};