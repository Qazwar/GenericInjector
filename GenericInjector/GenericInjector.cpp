#include "stdafx.h"
#include "GenericInjector.h"

namespace
{
	// Used for injecting stdcall function which prototype is same as function InjectorHelper
	// Avoid using ecx and edx because they may be used in function calling
	const byte InjectTemplate[] = {
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

	__declspec(noinline)
	void __stdcall InjectorHelper(FunctionInjectorBase* pInjector, LPVOID pStackTop)
	{
		pInjector->Execute(pStackTop);
	}

	byte* AllocCode(size_t szCode)
	{
		return static_cast<byte*>(VirtualAlloc(NULL, szCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	}

	void FlushCode(HINSTANCE hInstance, const byte* pCode, size_t szCode)
	{
		FlushInstructionCache(hInstance, pCode, szCode);
	}
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

byte* GenerateInjectImportTableEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize)
{
	byte* pInjectImportTableEntry = AllocCode(sizeof InjectTemplate);
	memcpy_s(pInjectImportTableEntry, sizeof InjectTemplate, InjectTemplate, sizeof InjectTemplate);
	*reinterpret_cast<LPVOID*>(pInjectImportTableEntry + 7) = pInjector;
	*reinterpret_cast<LPVOID*>(pInjectImportTableEntry + 12) = &InjectorHelper;
	*reinterpret_cast<WORD*>(pInjectImportTableEntry + 23) = static_cast<WORD>(dwArgSize);

	FlushCode(hInstance, pInjectImportTableEntry, sizeof InjectTemplate);

	return pInjectImportTableEntry;
}