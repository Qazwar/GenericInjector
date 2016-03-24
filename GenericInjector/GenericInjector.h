#pragma once
#include "InjectedFunction.h"
#include "PEParser.h"
#include <stdexcept>
#include <unordered_set>

class GenericInjector
{
public:
	GenericInjector() = default;
	virtual ~GenericInjector();

	void Init(HMODULE hDll);
	void Uninit();

	void SetInstance(LPCTSTR lpModuleName = NULL) noexcept
	{
		SetInstance(GetModuleHandle(lpModuleName));
	}

	void SetInstance(HMODULE hModule) noexcept;

	HMODULE GetInstance() const noexcept
	{
		return m_hInstance;
	}

	HMODULE GetModule() const noexcept
	{
		return m_hDll;
	}

	PEPaser const& GetPEPaser();

	template <typename FunctionPrototype>
	FunctionInjector<FunctionPrototype>* InjectImportTable(tstring const& DllName, tstring const& FuncName)
	{
		auto const& tPaser = GetPEPaser();
		if (!tPaser.DllImported(DllName))
		{
			throw std::invalid_argument("Cannot locate dll.");
		}

		return InjectFunctionPointer<FunctionPrototype>(tPaser.GetImportFunctionAddress(DllName, FuncName));
	}

	template <typename FunctionPrototype>
	FunctionInjector<FunctionPrototype>* InjectImportTable(tstring const& DllName, DWORD Index)
	{
		auto const& tPaser = GetPEPaser();

		if (!tPaser.DllImported(DllName))
		{
			throw std::invalid_argument("Cannot locate dll.");
		}

		return InjectFunctionPointer<FunctionPrototype>(tPaser.GetImportFunctionAddress(DllName, Index));
	}

	// Only tested on Visual Studio 2015
	template <typename FunctionPrototype>
	FunctionInjector<FunctionPrototype>* InjectVirtualTable(LPVOID pObject, DWORD dwIndex)
	{
		return InjectFunctionPointer<FunctionPrototype>(*static_cast<LPDWORD*>(pObject) + dwIndex);
	}

protected:
	virtual void OnLoad() = 0;
	virtual void OnUnload() = 0;

protected:
	static void InjectPointer(LPDWORD lpAddr, DWORD dwPointer);

	// Cannot call this in hooking function because unhooking will delete the injector
	void UnhookInjector(DWORD FunctionAddr);

	template <typename Container>
	static void GetCode(HMODULE hInstance, DWORD dwOffset, DWORD dwSize, Container& container)
	{
		byte* pCode = reinterpret_cast<byte*>(hInstance) + dwOffset;
		DWORD oldProtect;
		if (!VirtualProtect(pCode, dwSize, PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
		}
		container.insert(container.end(), pCode, pCode + dwSize);
		if (!VirtualProtect(pCode, dwSize, oldProtect, &oldProtect))
		{
			throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
		}
	}

	template <size_t Size>
	static void GetCode(HMODULE hInstance, DWORD dwOffset, byte (&Buffer)[Size])
	{
		byte* pCode = reinterpret_cast<byte*>(hInstance) + dwOffset;
		DWORD oldProtect;
		if (!VirtualProtect(pCode, Size, PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
		}
		memcpy_s(Buffer, Size, pCode, Size);
		if (!VirtualProtect(pCode, Size, oldProtect, &oldProtect))
		{
			throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
		}
	}

	static void ModifyCode(HMODULE hInstance, DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize);

private:
	HMODULE m_hDll, m_hInstance;
	std::unique_ptr<PEPaser> m_pPEPaser;
	std::unordered_map<DWORD, std::pair<std::unordered_set<LPDWORD>, std::unique_ptr<FunctionInjectorBase>>> m_InjectorMap;

	static byte* GenerateInjectStdcallEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize) noexcept;
	static byte* GenerateInjectCdeclEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize) noexcept;

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
		byte* pInjectStdcallEntry = GenerateInjectStdcallEntry(hInstance, pInjector, GetFunctionAnalysis<FunctionPrototype>::FunctionAnalysis::ArgType::Size);

		pInjector->m_ReplacedFunc.first = std::move(std::make_unique<InjectedFunction<FunctionPrototype>>(reinterpret_cast<FunctionPrototype>(*lpAddr)));
		pInjector->m_ReplacedFunc.second = nullptr;
		InjectPointer(lpAddr, reinterpret_cast<DWORD>(pInjectStdcallEntry));
	}

	template <typename FunctionPrototype>
	void InjectCdeclFunction(HINSTANCE hInstance, FunctionInjector<FunctionPrototype>* pInjector, LPDWORD lpAddr)
	{
		byte* pInjectCdeclEntry = GenerateInjectCdeclEntry(hInstance, pInjector, GetFunctionAnalysis<FunctionPrototype>::FunctionAnalysis::ArgType::Size);

		pInjector->m_ReplacedFunc.first = std::move(std::make_unique<InjectedFunction<FunctionPrototype>>(reinterpret_cast<FunctionPrototype>(*lpAddr)));
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

// define InitInjector before including GenericInjector.h if you need another DllMain
// why you want to do that?
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