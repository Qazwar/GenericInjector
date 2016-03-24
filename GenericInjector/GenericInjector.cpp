#include "GenericInjector.h"

namespace
{
	// Used for injecting stdcall function which prototype is same as function InjectorHelper
	// Avoid using ecx and edx because they may be used in function calling
	const byte InjectStdcallTemplate[] = {
		0x53,								//push ebx
		0x8D, 0x5C, 0x24, 0x08,				//lea ebx, [esp+8] // skip saved ebx and ret addr which is pushed by instruction call
		0x56,								//push esi
		0xBE, 0x00, 0x00, 0x00, 0x00,		//mov esi, 0x00000000(+7)
		0xB8, 0x00, 0x00, 0x00, 0x00,		//mov eax, 0x00000000(+C)
		0x53,								//push ebx
		0x56,								//push esi
		0xFF, 0xD0,							//call eax
		0x5E,								//pop esi
		0x5B,								//pop ebx
		0xC2, 0x00, 0x00,					//ret 0 // clear the stack and return
	};

	const byte InjectCdeclTemplate[] = {
		0x53,								//push ebx
		0x8D, 0x5C, 0x24, 0x08,				//lea ebx, [esp+8] // skip saved ebx and ret addr which is pushed by instruction call
		0x56,								//push esi
		0xBE, 0x00, 0x00, 0x00, 0x00,		//mov esi, 0x00000000(+7)
		0xB8, 0x00, 0x00, 0x00, 0x00,		//mov eax, 0x00000000(+C)
		0x53,								//push ebx
		0x56,								//push esi
		0xFF, 0xD0,							//call eax
		0x5E,								//pop esi
		0x5B,								//pop ebx
		0xC3,								//retn // return
	};

	__declspec(noinline)
	void __stdcall InjectorHelper(FunctionInjectorBase* pInjector, LPVOID pStackTop)
	{
		pInjector->Execute(pStackTop);
	}

	byte* AllocCode(size_t szCode) noexcept
	{
		return static_cast<byte*>(VirtualAlloc(NULL, szCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	}

	void FlushCode(HINSTANCE hInstance, const byte* pCode, size_t szCode) noexcept
	{
		FlushInstructionCache(hInstance, pCode, szCode);
	}
}

GenericInjector::~GenericInjector()
{
	for (auto const& i : m_InjectorMap)
	{
		UnhookInjector(i.first);
	}
}

void GenericInjector::Init(HMODULE hDll)
{
	m_hDll = hDll;
	SetInstance();
	OnLoad();
}

void GenericInjector::Uninit()
{
	OnUnload();
}

void GenericInjector::SetInstance(HMODULE hModule) noexcept
{
	if (m_hInstance != hModule)
	{
		m_pPEPaser.reset();
		m_hInstance = hModule;
	}
}

PEPaser const& GenericInjector::GetPEPaser()
{
	if (!m_pPEPaser)
	{
		m_pPEPaser = std::move(std::make_unique<PEPaser>(reinterpret_cast<const byte*>(GetInstance())));
	}

	return *m_pPEPaser;
}

void GenericInjector::InjectPointer(LPDWORD lpAddr, DWORD dwPointer)
{
	DWORD tOldProtect;
	if (!VirtualProtect(lpAddr, sizeof(LPVOID), PAGE_READWRITE, &tOldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of injected function.");
	}
	*lpAddr = dwPointer;
	if (!VirtualProtect(lpAddr, sizeof(LPVOID), tOldProtect, &tOldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of inject function");
	}
}

void GenericInjector::UnhookInjector(DWORD FunctionAddr)
{
	auto itea = m_InjectorMap.find(FunctionAddr);
	if (itea != m_InjectorMap.end())
	{
		for (auto InjectedAddr : itea->second.first)
		{
			// <FIXME>: Memory leaks
			InjectPointer(InjectedAddr, FunctionAddr);
		}

		itea->second.first.clear();
		itea->second.second.reset();
	}
}

byte* GenericInjector::GenerateInjectStdcallEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize) noexcept
{
	byte* pInjectStdcallEntry = AllocCode(sizeof InjectStdcallTemplate);
	memcpy_s(pInjectStdcallEntry, sizeof InjectStdcallTemplate, InjectStdcallTemplate, sizeof InjectStdcallTemplate);
	*reinterpret_cast<LPVOID*>(pInjectStdcallEntry + 7) = pInjector;
	*reinterpret_cast<LPVOID*>(pInjectStdcallEntry + 12) = &InjectorHelper;
	*reinterpret_cast<WORD*>(pInjectStdcallEntry + 23) = static_cast<WORD>(dwArgSize);

	FlushCode(hInstance, pInjectStdcallEntry, sizeof InjectStdcallTemplate);

	return pInjectStdcallEntry;
}

byte* GenericInjector::GenerateInjectCdeclEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize) noexcept
{
	byte* pInjectCdeclEntry = AllocCode(sizeof InjectCdeclTemplate);
	memcpy_s(pInjectCdeclEntry, sizeof InjectCdeclTemplate, InjectCdeclTemplate, sizeof InjectCdeclTemplate);
	*reinterpret_cast<LPVOID*>(pInjectCdeclEntry + 7) = pInjector;
	*reinterpret_cast<LPVOID*>(pInjectCdeclEntry + 12) = &InjectorHelper;

	FlushCode(hInstance, pInjectCdeclEntry, sizeof InjectCdeclTemplate);

	return pInjectCdeclEntry;
}