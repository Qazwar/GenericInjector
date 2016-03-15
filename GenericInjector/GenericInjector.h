#pragma once
#include "InjectedFunction.h"
#include "PEParser.h"
#include <stdexcept>

byte* GenerateInjectImportTableEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize);

class GenericInjector
{
public:
	GenericInjector() = default;
	virtual ~GenericInjector() = default;

	void Init(HMODULE hDll)
	{
		m_hDll = hDll;
		SetInstance();
		OnLoad();
	}

	void Uninit()
	{
		OnUnload();
	}

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

	// Only tested on Visual Studio
	template <typename FunctionPrototype>
	FunctionInjector<FunctionPrototype>* InjectVirtualTable(LPVOID pObject, DWORD dwIndex)
	{
		return InjectFunctionPointer<FunctionPrototype>(*static_cast<LPDWORD*>(pObject) + dwIndex);
	}

protected:
	virtual void OnLoad() = 0;
	virtual void OnUnload() = 0;

private:
	HMODULE m_hDll, m_hInstance;
	std::unique_ptr<PEPaser> m_pPEPaser;
	std::unordered_map<DWORD, FunctionInjectorBase*> m_InjectorMap;

	// TODO: Free injectors safely
	// ¡üThis is no necessary now
	template <typename FunctionPrototype>
	FunctionInjector<FunctionPrototype>* AllocInjector(DWORD FunctionAddr)
	{
		auto tItea = m_InjectorMap.find(FunctionAddr);
		if (tItea == m_InjectorMap.end())
		{
			auto tRet = new FunctionInjector<FunctionPrototype>;
			m_InjectorMap[FunctionAddr] = tRet;
			return tRet;
		}

		if (!tItea->second)
		{
			auto tRet = new FunctionInjector<FunctionPrototype>;
			tItea->second = tRet;
			return tRet;
		}

		return dynamic_cast<FunctionInjector<FunctionPrototype>*>(tItea->second);
	}
	
	template <typename FunctionPrototype>
	void InjectStdCallFunction(HINSTANCE hInstance, FunctionInjector<FunctionPrototype>* pInjector, LPDWORD lpAddr)
	{
		byte* pInjectImportTableEntry = GenerateInjectImportTableEntry(hInstance, pInjector, GetFunctionAnalysis<FunctionPrototype>::FunctionAnalysis::ArgType::Size);

		DWORD tOldProtect;
		if (!VirtualProtect(lpAddr, sizeof(LPVOID), PAGE_READWRITE, &tOldProtect))
		{
			throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of inject function");
		}

		pInjector->m_ReplacedFunc = std::move(std::make_unique<InjectedFunction<FunctionPrototype>>(reinterpret_cast<FunctionPrototype>(*lpAddr)));
		*lpAddr = reinterpret_cast<DWORD>(pInjectImportTableEntry);
		if (!VirtualProtect(lpAddr, sizeof(LPVOID), tOldProtect, &tOldProtect))
		{
			throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of inject function");
		}
	}

	template <typename FunctionPrototype>
	FunctionInjector<FunctionPrototype>* InjectFunctionPointer(LPDWORD lpAddr)
	{
		if (!lpAddr || !*lpAddr)
		{
			throw std::invalid_argument("lpAddr or address which lpAddr points to should not be a nullptr.");
		}

		auto pInjector = AllocInjector<FunctionPrototype>(*lpAddr);

		// Now we can only inject stdcall function
		switch (GetFunctionAnalysis<FunctionPrototype>::FunctionAnalysis::CallingConvention)
		{
		case CallingConventionEnum::Thiscall:
		case CallingConventionEnum::Stdcall:
			InjectStdCallFunction(GetInstance(), pInjector, lpAddr);
			break;
		case CallingConventionEnum::Cdecl:
			break;
		case CallingConventionEnum::Fastcall:
			break;
		default:
			break;
		}

		return pInjector;
	}
};

#define InitInjector(Injector) \
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