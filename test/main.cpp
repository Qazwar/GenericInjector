#include <iostream>
#include <string>

#define NOMINMAX 1
#include <Windows.h>
#include <tchar.h>

typedef unsigned int uint;
typedef uint8_t byte;

bool CreateProcessWithDll(LPCTSTR lpExePath, LPCTSTR lpDllPath)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);

	if (!CreateProcess(lpExePath, NULL, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		return false;
	}

	SIZE_T szMem = _tcslen(lpDllPath) * sizeof(TCHAR);
	LPVOID pRemoteAddr = VirtualAllocEx(pi.hProcess, NULL, szMem + sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
	if (!pRemoteAddr || !WriteProcessMemory(pi.hProcess, pRemoteAddr, lpDllPath, szMem, NULL))
	{
		return false;
	}

	auto hModule = GetModuleHandle(_T("Kernel32"));
	if (!hModule)
	{
		return false;
	}
	LPTHREAD_START_ROUTINE lpRoutine = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(hModule,
#ifdef UNICODE
		"LoadLibraryW"
#else
		"LoadLibraryA"
#endif
		));

	if (!lpRoutine)
	{
		return false;
	}
	
	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0u,
		lpRoutine,
		pRemoteAddr, NULL, NULL
		);

	if (hThread == INVALID_HANDLE_VALUE || !hThread)
	{
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	ResumeThread(pi.hThread);

	DWORD dwReturn;
	GetExitCodeThread(hThread, &dwReturn);
	return dwReturn != 0ul;
}

int main()
{
	/*std::wstring strExe;
	std::wcin >> strExe;
	if (!CreateProcessWithDll(strExe.c_str(), _T("InjectorTest.dll")))
	{
		MessageBox(NULL, _T("Failed"), _T("Error"), MB_OK);
	}*/
	
	// Load our injector, you can also do this by CreateRemoteThread or edit Import table
	LoadLibrary(_T("InjectorTest.dll"));

	// Address of MessageBoxW will change if our injection succeed
	std::cout << MessageBox << std::endl << std::endl;
	std::wcout.imbue(std::locale("", LC_CTYPE));
	std::wcout << _T("返回值：") << MessageBox(NULL, _T("阁下果然是装逼高手"), _T("是在下输了"), MB_OKCANCEL | MB_ICONINFORMATION) << std::endl;

	putchar('w');

	system("pause");
	return 0;
}