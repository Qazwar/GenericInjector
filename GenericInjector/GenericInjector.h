#pragma once
#include "InjectedFunction.h"
#include "PEParser.h"
#include <stdexcept>
#include <unordered_set>
#include <iterator>

class GenericInjector
{
public:
	GenericInjector() = default;
	virtual ~GenericInjector();

	void Init(HMODULE hDll, LPCTSTR lpModuleName = nullptr);
	void Init(HMODULE hDll, HINSTANCE hInstance);
	void Uninit();

	HMODULE GetInstance() const noexcept
	{
		return m_hInstance;
	}

	HMODULE GetModule() const noexcept
	{
		return m_hDll;
	}

	HANDLE GetProcess() const noexcept
	{
		return m_hProcess;
	}

	PEPaser const& GetPEPaser();

	template <typename FunctionPrototype>
	auto InjectImportTable(tstring const& DllName, tstring const& FuncName)
	{
		auto const& tPaser = GetPEPaser();
		if (!tPaser.DllImported(DllName))
		{
			throw std::invalid_argument("Cannot locate dll.");
		}

		return InjectFunctionPointer<std::decay_t<FunctionPrototype>>(tPaser.GetImportFunctionAddress(DllName, FuncName));
	}

	template <typename FunctionPrototype>
	auto InjectImportTable(tstring const& DllName, DWORD Index)
	{
		auto const& tPaser = GetPEPaser();

		if (!tPaser.DllImported(DllName))
		{
			throw std::invalid_argument("Cannot locate dll.");
		}

		return InjectFunctionPointer<std::decay_t<FunctionPrototype>>(tPaser.GetImportFunctionAddress(DllName, Index));
	}

	// Only tested on Visual Studio 2015
	template <typename FunctionPrototype>
	auto InjectVirtualTable(LPVOID pObject, DWORD dwIndex)
	{
		return InjectFunctionPointer<std::decay_t<FunctionPrototype>>(*static_cast<LPDWORD*>(pObject) + dwIndex);
	}

	// Return address which match pattern you specified, or nullptr if not found
	// Search address from pAddressBase to pAddressEnd, if pAddressBase or pAddressEnd is nullptr then use default range
	byte* FindMemory(void* pAddressBase, void* pAddressEnd, const byte* pPattern, size_t PatternSize, const byte* pWildcard, size_t WildcardSize, size_t Alignment) noexcept;

	template <size_t PatternSize>
	byte* FindMemory(void* pAddressBase, void* pAddressEnd, const byte (&Pattern)[PatternSize], size_t Alignment) noexcept
	{
		return FindMemory(pAddressBase, pAddressEnd, Pattern, PatternSize, nullptr, 0, Alignment);
	}

	template <size_t PatternSize, size_t WildcardSize>
	byte* FindMemory(void* pAddressBase, void* pAddressEnd, const byte(&Pattern)[PatternSize], const byte(&Wildcard)[WildcardSize], size_t Alignment) noexcept
	{
		return FindMemory(pAddressBase, pAddressEnd, Pattern, PatternSize, Wildcard, WildcardSize, Alignment);
	}

protected:
	virtual void OnLoad() = 0;
	virtual void OnUnload() = 0;

protected:
	void InjectPointer(LPDWORD lpAddr, DWORD dwPointer) const;
	static void InjectPointer(HANDLE hProcess, LPDWORD lpAddr, DWORD dwPointer);

	// Cannot call this in hooking function because unhooking will delete the injector
	void UnhookInjector(DWORD FunctionAddr);

	template <typename Container>
	void GetCode(DWORD dwOffset, DWORD dwSize, Container& container) const
	{
		GetCode(GetProcess(), GetInstance(), dwOffset, dwSize, container);
	}

	template <size_t Size>
	void GetCode(DWORD dwOffset, byte(&Buffer)[Size]) const
	{
		GetCode(GetProcess(), GetInstance(), dwOffset, Buffer);
	}

	template <typename Container>
	static void GetCode(HANDLE hProcess, HMODULE hInstance, DWORD dwOffset, DWORD dwSize, Container& container)
	{
		std::vector<byte> Buffer(dwSize);
		GetCode(hProcess, hInstance, dwOffset, Buffer.data(), Buffer.size());
		std::copy(Buffer.begin(), Buffer.end(), std::back_inserter(container));
	}

	template <size_t Size>
	static void GetCode(HANDLE hProcess, HMODULE hInstance, DWORD dwOffset, byte (&Buffer)[Size])
	{
		GetCode(hProcess, hInstance, dwOffset, Buffer, Size);
	}

	static void GetCode(HANDLE hProcess, HMODULE hInstance, DWORD dwOffset, byte* pBuffer, size_t BufferSize);

	template <size_t Size>
	void InjectCode(DWORD dwDestOffset, DWORD dwDestSize, const byte(&Code)[Size]) const
	{
		InjectCode(GetProcess(), GetInstance(), dwDestOffset, dwDestSize, Code);
	}

	void InjectCode(DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize) const;

	template <size_t Size>
	static void InjectCode(HANDLE hProcess, HMODULE hInstance, DWORD dwDestOffset, DWORD dwDestSize, const byte (&Code)[Size])
	{
		InjectCode(hProcess, hInstance, dwDestOffset, dwDestSize, Code, Size);
	}
	static void InjectCode(HANDLE hProcess, HMODULE hInstance, DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize);

	template <size_t Size>
	void ModifyCode(DWORD dwDestOffset, DWORD dwDestSize, const byte(&Code)[Size], bool bFillNop = true) const
	{
		ModifyCode(GetProcess(), GetInstance(), dwDestOffset, dwDestSize, Code, bFillNop);
	}

	void ModifyCode(DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize, bool bFillNop = true) const;

	template <size_t Size>
	static void ModifyCode(HANDLE hProcess, HMODULE hInstance, DWORD dwDestOffset, DWORD dwDestSize, const byte (&Code)[Size], bool bFillNop = true)
	{
		ModifyCode(hProcess, hInstance, dwDestOffset, dwDestSize, Code, Size, bFillNop);
	}
	static void ModifyCode(HANDLE hProcess, HMODULE hInstance, DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize, bool bFillNop = true);

	static byte* GenerateJmpCode(HINSTANCE hInstance, DWORD TargetOffset);
	static byte* GenerateJmpCode(HINSTANCE hInstance, DWORD From, DWORD To);

private:
	bool m_Inited;
	HMODULE m_hDll, m_hInstance;
	HANDLE m_hProcess;
	std::unique_ptr<PEPaser> m_pPEPaser;
	std::unordered_map<DWORD, std::pair<std::unordered_set<LPDWORD>, std::unique_ptr<FunctionInjectorBase>>> m_InjectorMap;

	void SetInstance(LPCTSTR lpModuleName = NULL) noexcept
	{
		SetInstance(GetModuleHandle(lpModuleName));
	}

	void SetInstance(HMODULE hModule) noexcept;
	void SetProcess(HANDLE hProcess = INVALID_HANDLE_VALUE) noexcept;

	static byte* GenerateInjectStdcallEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize);
	static byte* GenerateInjectCdeclEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize);

	template <typename FunctionPrototype>
	FunctionInjector<FunctionPrototype>* AllocInjector(LPDWORD FunctionAddr)
	{
		auto tItea = m_InjectorMap.find(*FunctionAddr);
		if (tItea == m_InjectorMap.end())
		{
			auto tRet = new FunctionInjector<FunctionPrototype>;
			auto& InjectorPair = m_InjectorMap[*FunctionAddr];
			InjectorPair.first.insert(FunctionAddr);
			InjectorPair.second.reset(static_cast<FunctionInjectorBase*>(tRet));

			return tRet;
		}

		if (!tItea->second.second)
		{
			auto tRet = new FunctionInjector<FunctionPrototype>;
			tItea->second.first.insert(FunctionAddr);
			tItea->second.second.reset(static_cast<FunctionInjectorBase*>(tRet));

			return tRet;
		}

		return dynamic_cast<FunctionInjector<FunctionPrototype>*>(tItea->second.second.get());
	}
	
	template <typename FunctionPrototype>
	void InjectStdCallFunction(HINSTANCE hInstance, FunctionInjector<FunctionPrototype>* pInjector, LPDWORD lpAddr)
	{
		union
		{
			FunctionPrototype FunctionPointer;
			DWORD RawValue;
		} Bugfix;

		Bugfix.RawValue = *lpAddr;

		byte* pInjectStdcallEntry = GenerateInjectStdcallEntry(hInstance, pInjector, GetFunctionAnalysis<FunctionPrototype>::FunctionAnalysis::ArgType::Size);

		pInjector->m_OriginalFunction.OriginalFunctionPointer = Bugfix.FunctionPointer;
		pInjector->m_ReplacedFunc.first = std::move(std::make_unique<InjectedFunction<FunctionPrototype>>(Bugfix.FunctionPointer));
		pInjector->m_ReplacedFunc.second = nullptr;
		InjectPointer(lpAddr, reinterpret_cast<DWORD>(pInjectStdcallEntry));
	}

	template <typename FunctionPrototype>
	void InjectCdeclFunction(HINSTANCE hInstance, FunctionInjector<FunctionPrototype>* pInjector, LPDWORD lpAddr)
	{
		union
		{
			FunctionPrototype FunctionPointer;
			DWORD RawValue;
		} Bugfix;

		Bugfix.RawValue = *lpAddr;

		byte* pInjectCdeclEntry = GenerateInjectCdeclEntry(hInstance, pInjector, GetFunctionAnalysis<FunctionPrototype>::FunctionAnalysis::ArgType::Size);

		pInjector->m_OriginalFunction.OriginalFunctionPointer = Bugfix.FunctionPointer;
		pInjector->m_ReplacedFunc.first = std::move(std::make_unique<InjectedFunction<FunctionPrototype>>(Bugfix.FunctionPointer));
		pInjector->m_ReplacedFunc.second = nullptr;
		InjectPointer(lpAddr, reinterpret_cast<DWORD>(pInjectCdeclEntry));
	}

	template <typename FunctionPrototype>
	FunctionInjector<FunctionPrototype>* InjectFunctionPointer(LPDWORD lpAddr)
	{
		if (!lpAddr || !*lpAddr)
		{
			throw std::invalid_argument("lpAddr or address which lpAddr points to should not be a nullptr.");
		}

		auto pInjector = AllocInjector<FunctionPrototype>(lpAddr);
		if (!pInjector)
		{
			throw std::runtime_error("Failed to alloc injector.");
		}

		switch (GetFunctionAnalysis<FunctionPrototype>::FunctionAnalysis::CallingConvention)
		{
		case CallingConventionEnum::Stdcall:
		case CallingConventionEnum::Thiscall:
		case CallingConventionEnum::Fastcall:
			InjectStdCallFunction(GetInstance(), pInjector, lpAddr);
			break;
		case CallingConventionEnum::Cdecl:
			InjectCdeclFunction(GetInstance(), pInjector, lpAddr);
			break;
		default:
			throw std::invalid_argument("Unknown calling convention.");
		}

		return pInjector;
	}
};

#ifndef InitInjector
#	define InitInjector(Injector) \
	BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)\
	{\
		switch (ul_reason_for_call)\
		{\
		case DLL_PROCESS_ATTACH:\
			(Injector).Init(hModule);\
			break;\
		case DLL_THREAD_ATTACH:\
		case DLL_THREAD_DETACH:\
			break;\
		case DLL_PROCESS_DETACH:\
			(Injector).Uninit();\
			break;\
		}\
		return TRUE;\
	}
#endif
