#pragma once
#include <string>

template <typename Char_t>
struct CaseIgnoredStringEqualTo;

template <>
struct CaseIgnoredStringEqualTo<wchar_t>
{
	bool operator()(std::basic_string<wchar_t> const& a, std::basic_string<wchar_t> const& b) const noexcept
	{
		return lstrcmpiW(a.c_str(), b.c_str()) == 0;
	}
};

template <>
struct CaseIgnoredStringEqualTo<char>
{
	bool operator()(std::basic_string<char> const& a, std::basic_string<char> const& b) const noexcept
	{
		return lstrcmpiA(a.c_str(), b.c_str()) == 0;
	}
};

typedef std::basic_string<TCHAR> tstring;

template <typename Itea>
__forceinline tstring GetTString(Itea i1, Itea i2)
{
	return tstring(i1, i2);
}

template <typename Container>
__forceinline tstring GetTString(Container const& container)
{
	return GetTString(container.begin(), container.end());
}