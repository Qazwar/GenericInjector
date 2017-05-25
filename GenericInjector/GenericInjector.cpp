#include "GenericInjector.h"
#include <algorithm>

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
		auto pCode = static_cast<byte*>(VirtualAllocEx(hProcess == INVALID_HANDLE_VALUE || !hProcess ? GetCurrentProcess() : hProcess, NULL, szCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
		if (!pCode)
		{
			throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot alloc code.");
		}
		return pCode;
	}

	void FreeCode(byte* pMem, HANDLE hProcess = INVALID_HANDLE_VALUE)
	{
		VirtualFreeEx(hProcess == INVALID_HANDLE_VALUE || !hProcess ? GetCurrentProcess() : hProcess, pMem, NULL, MEM_RELEASE);
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
	if (m_Inited)
	{
		throw std::runtime_error("Injector already initialized.");
	}

	m_hDll = hDll;
	SetProcess();
	SetInstance(hInstance);
	m_Inited = true;
	OnLoad();
}

void GenericInjector::Uninit()
{
	if (!m_Inited)
	{
		throw std::runtime_error("Injector have not initialized.");
	}

	m_Inited = false;
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

void GenericInjector::SetProcess(HANDLE hProcess) noexcept
{
	m_hProcess = hProcess == INVALID_HANDLE_VALUE || !hProcess ? GetCurrentProcess() : hProcess;
}

PEPaser const& GenericInjector::GetPEPaser()
{
	if (!m_pPEPaser)
	{
		m_pPEPaser = std::move(std::make_unique<PEPaser>(reinterpret_cast<const byte*>(GetInstance())));
	}

	return *m_pPEPaser;
}

byte* GenericInjector::FindMemory(void* pAddressBase, void* pAddressEnd, const byte* pPattern, size_t PatternSize, const byte* pWildcard, size_t WildcardSize, size_t Alignment) noexcept
{
	if (!pPattern || !PatternSize || !Alignment)
	{
		return nullptr;
	}

	const size_t FirstSectionRVA = GetPEPaser().GetSections().front().VirtualAddress;
	const size_t MemSize = GetPEPaser().GetNTHeaders().OptionalHeader.SizeOfImage - std::max(PatternSize, Alignment) - FirstSectionRVA;

	byte* pStart = reinterpret_cast<byte*>(GetInstance()) + FirstSectionRVA;
	byte* pEndPointer = pStart + MemSize;

	byte* pCurrentPointer = static_cast<byte*>(pAddressBase);
	if (pCurrentPointer < pStart)
	{
		pCurrentPointer = pStart;
	}
	else if (pCurrentPointer >= pEndPointer)
	{
		return nullptr;
	}

	if (pAddressEnd && pAddressEnd < pEndPointer)
	{
		if (pAddressEnd <= pCurrentPointer)
		{
			return nullptr;
		}

		pEndPointer = static_cast<byte*>(pAddressEnd);
	}

	if (IsBadReadPtr(pCurrentPointer, MemSize))
	{
		return nullptr;
	}

	if (!pWildcard)
	{
		WildcardSize = 0;
	}

	for (; pCurrentPointer < pEndPointer; pCurrentPointer += Alignment)
	{
		for (size_t i = 0; i < PatternSize; ++i)
		{
			if (pCurrentPointer[i] != pPattern[i])
			{
				for (size_t j = 0; j < WildcardSize; ++j)
				{
					if (pPattern[i] == pWildcard[j])
					{
						goto WildcardMatched;
					}
				}
				goto NotMatched;
			}
		WildcardMatched:
			continue;
		}
		return pCurrentPointer;
	NotMatched:
		continue;
	}

	return nullptr;
}

void GenericInjector::InjectPointer(LPDWORD lpAddr, DWORD dwPointer) const
{
	InjectPointer(GetProcess(), lpAddr, dwPointer);
}

void GenericInjector::InjectPointer(HANDLE hProcess, LPDWORD lpAddr, DWORD dwPointer)
{
	if (hProcess == INVALID_HANDLE_VALUE || !hProcess)
	{
		hProcess = GetCurrentProcess();
	}

	DWORD tOldProtect;

	if (!VirtualProtectEx(hProcess, lpAddr, sizeof(LPVOID), PAGE_READWRITE, &tOldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of injected function.");
	}
	*lpAddr = dwPointer;
	if (!VirtualProtectEx(hProcess, lpAddr, sizeof(LPVOID), tOldProtect, &tOldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of injected function.");
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

void GenericInjector::GetCode(HANDLE hProcess, HMODULE hInstance, DWORD dwOffset, byte* pBuffer, size_t BufferSize)
{
	if (hProcess == INVALID_HANDLE_VALUE || !hProcess)
	{
		hProcess = GetCurrentProcess();
	}

	if (hInstance == INVALID_HANDLE_VALUE || !hInstance || !pBuffer || !BufferSize)
	{
		throw std::invalid_argument("Invalid argument.");
	}

	byte* pCode = reinterpret_cast<byte*>(hInstance) + dwOffset;
	DWORD oldProtect;
	if (!VirtualProtectEx(hProcess, pCode, BufferSize, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
	}
	memcpy_s(pBuffer, BufferSize, pCode, BufferSize);
	if (!VirtualProtectEx(hProcess, pCode, BufferSize, oldProtect, &oldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
	}
}

void GenericInjector::InjectCode(DWORD dwDestOffset, DWORD dwDestSize, const byte * lpCode, DWORD dwCodeSize) const
{
	InjectCode(GetProcess(), GetInstance(), dwDestOffset, dwDestSize, lpCode, dwCodeSize);
}

void GenericInjector::InjectCode(HANDLE hProcess, HMODULE hInstance, DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize)
{
	if (hProcess == INVALID_HANDLE_VALUE || !hProcess)
	{
		hProcess = GetCurrentProcess();
	}

	if (hInstance == INVALID_HANDLE_VALUE || !hInstance || !lpCode)
	{
		throw std::invalid_argument("Invalid argument.");
	}

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
	FlushInstructionCache(hInstance, pNewCode, dwCodeSize + sizeof JmpTemplate);
	
	*reinterpret_cast<DWORD*>(pJmpCode + 1) = static_cast<DWORD>(pNewCode - pDest - sizeof pJmpCode);
	DWORD oldProtect;
	if (!VirtualProtectEx(hProcess, pDest, dwDestSize, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
	}
	memcpy_s(pDest, dwDestSize, pJmpCode, sizeof pJmpCode);
	if (!VirtualProtectEx(hProcess, pDest, dwDestSize, oldProtect, &oldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
	}
}

void GenericInjector::ModifyCode(DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize, bool bFillNop) const
{
	ModifyCode(GetProcess(), GetInstance(), dwDestOffset, dwDestSize, lpCode, dwCodeSize, bFillNop);
}

void GenericInjector::ModifyCode(HANDLE hProcess, HMODULE hInstance, DWORD dwDestOffset, DWORD dwDestSize, const byte* lpCode, DWORD dwCodeSize, bool bFillNop)
{
	if (hProcess == INVALID_HANDLE_VALUE || !hProcess)
	{
		hProcess = GetCurrentProcess();
	}

	if (hInstance == INVALID_HANDLE_VALUE || !hInstance || !lpCode)
	{
		throw std::invalid_argument("Invalid argument.");
	}

	if (dwDestSize < dwCodeSize)
	{
		throw std::invalid_argument("Size of code is too big, consider using InjectCode.");
	}

	byte* pDest = reinterpret_cast<byte*>(hInstance) + dwDestOffset;
	DWORD oldProtect;
	if (!VirtualProtectEx(hProcess, pDest, dwDestSize, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		throw std::system_error(std::error_code(GetLastError(), std::system_category()), "Cannot modify the protect of code.");
	}
	memcpy_s(pDest, dwDestSize, lpCode, dwCodeSize);
	if (dwDestSize > dwCodeSize && bFillNop)
	{
		// NOP: 0x90
		memset(pDest + dwCodeSize, 0x90, dwDestSize - dwCodeSize);
	}
	if (!VirtualProtectEx(hProcess, pDest, dwDestSize, oldProtect, &oldProtect))
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
	
	FlushInstructionCache(hInstance, pInjectStdcallEntry, sizeof InjectStdcallTemplate);

	return pInjectStdcallEntry;
}

byte* GenericInjector::GenerateInjectCdeclEntry(HINSTANCE hInstance, LPVOID pInjector, DWORD dwArgSize)
{
	byte* pInjectCdeclEntry = AllocCode(sizeof InjectCdeclTemplate);
	memcpy_s(pInjectCdeclEntry, sizeof InjectCdeclTemplate, InjectCdeclTemplate, sizeof InjectCdeclTemplate);
	*reinterpret_cast<LPVOID*>(pInjectCdeclEntry + 7) = pInjector;
	*reinterpret_cast<LPVOID*>(pInjectCdeclEntry + 12) = &InjectorHelper;

	FlushInstructionCache(hInstance, pInjectCdeclEntry, sizeof InjectCdeclTemplate);

	return pInjectCdeclEntry;
}

byte* GenericInjector::GenerateJmpCode(HINSTANCE hInstance, DWORD TargetOffset)
{
	byte* pJmpCode = AllocCode(sizeof JmpTemplate);
	memcpy_s(pJmpCode, sizeof JmpTemplate, JmpTemplate, sizeof JmpTemplate);
	*reinterpret_cast<DWORD*>(pJmpCode + 1) = TargetOffset;

	FlushInstructionCache(hInstance, pJmpCode, sizeof JmpTemplate);

	return pJmpCode;
}

byte* GenericInjector::GenerateJmpCode(HINSTANCE hInstance, DWORD From, DWORD To)
{
	return GenerateJmpCode(hInstance, To - From);
}
