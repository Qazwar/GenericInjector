#include "GenericInjector.h"

namespace
{
	// Used for injecting stdcall function which prototype is same as function InjectorHelper
	// Avoid using ecx and edx because they may be used in function calling
	const byte InjectStdcallTemplate[]
	{
		0x53,								//push ebx
		0x8D, 0x5C, 0x24, 0x08,				//lea ebx, [esp+8] // skip saved ebx and ret addr which is pushed by instruction call
		0x56,								//push esi
		0xBE, 0x00, 0x00, 0x00, 0x00,		//mov esi, 0x00000000(+0x7)
		0xB8, 0x00, 0x00, 0x00, 0x00,		//mov eax, 0x00000000(+0xC)
		0x53,								//push ebx
		0x51,								//push ecx
		0x56,								//push esi
		0xFF, 0xD0,							//call eax
		0x5E,								//pop esi
		0x5B,								//pop ebx
		0xC2, 0x00, 0x00,					//ret 0(+0x18) // clear the stack and return
	};

	const byte InjectCdeclTemplate[]
	{
		0x53,								//push ebx
		0x8D, 0x5C, 0x24, 0x08,				//lea ebx, [esp+8] // skip saved ebx and ret addr which is pushed by instruction call
		0x56,								//push esi
		0xBE, 0x00, 0x00, 0x00, 0x00,		//mov esi, 0x00000000(+7)
		0xB8, 0x00, 0x00, 0x00, 0x00,		//mov eax, 0x00000000(+C)
		0x53,								//push ebx
		0x51,								//push ecx
		0x56,								//push esi
		0xFF, 0xD0,							//call eax
		0x5E,								//pop esi
		0x5B,								//pop ebx
		0xC3,								//retn // return
	};

	const byte JmpTemplate[]
	{
		0xE9, 0x00, 0x00, 0x00, 0x00,		//jmp 0x00000000(+1) // offset
	};

	__declspec(noinline)
	void __stdcall InjectorHelper(FunctionInjectorBase* pInjector, DWORD dwECX, LPVOID pStackTop)
	{
		pInjector->Execute(dwECX, pStackTop);
	}

	byte* AllocCode(size_t szCode, HANDLE hProcess = INVALID_HANDLE_VALUE)
	{
		auto pCode = static_cast<byte*>(VirtualAllocEx(hProcess == INVALID_HANDLE_VALUE ? GetCurrentProcess() : hProcess, NULL, szCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
		if (!pCode)
		{
			throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot alloc code.");
		}
		return pCode;
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

void GenericInjector::Init(HMODULE hDll, LPCTSTR lpModuleName)
{
	Init(hDll, GetModuleHandle(lpModuleName));
}

void GenericInjector::Init(HMODULE hDll, HINSTANCE hInstance)
{
	if (m_bInit)
	{
		throw std::runtime_error("Injector already initialized.");
	}

	m_hDll = hDll;
	SetProcess();
	SetInstance(hInstance);
	OnLoad();
	m_bInit = true;
}

void GenericInjector::Uninit()
{
	if (!m_bInit)
	{
		throw std::runtime_error("Injector have not initialized.");
	}

	OnUnload();
	m_bInit = false;
}

void GenericInjector::SetInstance(HMODULE hModule) noexcept
{
	if (m_hInstance != hModule)
	{
		m_pPEPaser.reset();
		m_hInstance = hModule;
	}
}

void GenericInjector::SetProcess(HANDLE hProcess) noexcept
{
	m_hProcess = hProcess == INVALID_HANDLE_VALUE ? GetCurrentProcess() : hProcess;
}

PEPaser const& GenericInjector::GetPEPaser()
{
	if (!m_pPEPaser)
	{
		m_pPEPaser = std::move(std::make_unique<PEPaser>(reinterpret_cast<const byte*>(GetInstance())));
	}

	return *m_pPEPaser;
}

void GenericInjector::InjectPointer(LPDWORD lpAddr, DWORD dwPointer) const
{
	InjectPointer(GetInstance(), lpAddr, dwPointer);
}

void GenericInjector::InjectPointer(HINSTANCE hInstance, LPDWORD lpAddr, DWORD dwPointer)
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

void GenericInjector::InjectCode(HMODULE hInstance, DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize)
{
	if (dwDestSize < sizeof JmpTemplate)
	{
		throw std::invalid_argument("Size of dest code should be at least bigger than JmpTemplate.");
	}

	byte* pDest = reinterpret_cast<byte*>(hInstance) + dwDestOffset;
	byte* pNewCode = AllocCode(dwCodeSize + sizeof JmpTemplate);
	memcpy_s(pNewCode, dwCodeSize + sizeof JmpTemplate, lpCode, dwCodeSize);
	byte pJmpCode[sizeof JmpTemplate];
	memcpy_s(pJmpCode, sizeof JmpTemplate, JmpTemplate, sizeof JmpTemplate);
	*reinterpret_cast<DWORD*>(pJmpCode + 1) = static_cast<DWORD>(pDest + dwDestSize - (pNewCode + dwCodeSize) - sizeof pJmpCode);
	memcpy_s(pNewCode + dwCodeSize, sizeof JmpTemplate, pJmpCode, sizeof pJmpCode);
	FlushCode(hInstance, pNewCode, dwCodeSize + sizeof JmpTemplate);
	
	*reinterpret_cast<DWORD*>(pJmpCode + 1) = static_cast<DWORD>(pNewCode - pDest - sizeof pJmpCode);
	DWORD oldProtect;
	if (!VirtualProtect(pDest, dwDestSize, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
	}
	memcpy_s(pDest, dwDestSize, pJmpCode, sizeof pJmpCode);
	if (!VirtualProtect(pDest, dwDestSize, oldProtect, &oldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
	}
}

void GenericInjector::ModifyCode(HMODULE hInstance, DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize, bool bFillNop)
{
	if (dwDestSize < dwCodeSize)
	{
		throw std::invalid_argument("Size of code is too big, consider using InjectCode.");
	}

	byte* pDest = reinterpret_cast<byte*>(hInstance) + dwDestOffset;
	DWORD oldProtect;
	if (!VirtualProtect(pDest, dwDestSize, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
	}
	memcpy_s(pDest, dwDestSize, lpCode, dwCodeSize);
	if (dwDestSize > dwCodeSize && bFillNop)
	{
		// NOP: 0x90
		memset(pDest + dwCodeSize, 0x90, dwDestSize - dwCodeSize);
	}
	if (!VirtualProtect(pDest, dwDestSize, oldProtect, &oldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
	}
}

byte* GenericInjector::GenerateInjectStdcallEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize)
{
	byte* pInjectStdcallEntry = AllocCode(sizeof InjectStdcallTemplate);
	memcpy_s(pInjectStdcallEntry, sizeof InjectStdcallTemplate, InjectStdcallTemplate, sizeof InjectStdcallTemplate);
	*reinterpret_cast<LPVOID*>(pInjectStdcallEntry + 7) = pInjector;
	*reinterpret_cast<LPVOID*>(pInjectStdcallEntry + 12) = &InjectorHelper;
	*reinterpret_cast<WORD*>(pInjectStdcallEntry + 24) = static_cast<WORD>(dwArgSize);
	
	FlushCode(hInstance, pInjectStdcallEntry, sizeof InjectStdcallTemplate);

	return pInjectStdcallEntry;
}

byte* GenericInjector::GenerateInjectCdeclEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize)
{
	byte* pInjectCdeclEntry = AllocCode(sizeof InjectCdeclTemplate);
	memcpy_s(pInjectCdeclEntry, sizeof InjectCdeclTemplate, InjectCdeclTemplate, sizeof InjectCdeclTemplate);
	*reinterpret_cast<LPVOID*>(pInjectCdeclEntry + 7) = pInjector;
	*reinterpret_cast<LPVOID*>(pInjectCdeclEntry + 12) = &InjectorHelper;

	FlushCode(hInstance, pInjectCdeclEntry, sizeof InjectCdeclTemplate);

	return pInjectCdeclEntry;
}

byte* GenericInjector::GenerateJmpCode(HINSTANCE hInstance, DWORD TargetOffset)
{
	byte* pJmpCode = AllocCode(sizeof JmpTemplate);
	memcpy_s(pJmpCode, sizeof JmpTemplate, JmpTemplate, sizeof JmpTemplate);
	*reinterpret_cast<DWORD*>(pJmpCode + 1) = TargetOffset;

	FlushCode(hInstance, pJmpCode, sizeof JmpTemplate);

	return pJmpCode;
}

byte* GenericInjector::GenerateJmpCode(HINSTANCE hInstance, DWORD From, DWORD To)
{
	return GenerateJmpCode(hInstance, To - From);
}
