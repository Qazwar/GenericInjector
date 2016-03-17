#include <iostream>

#define NOMINMAX 1
#include <Windows.h>
#include <tchar.h>

typedef unsigned int uint;
typedef uint8_t byte;

int main()
{
	// Load our injector, you can also do this by CreateRemoteThread or edit Import table
	LoadLibrary(_T("InjectorTest.dll"));
	
	// Address of MessageBoxW will change if our injection succeed
	std::cout << MessageBoxW << std::endl << std::endl;
	std::wcout.imbue(std::locale("", LC_CTYPE));
	std::wcout << _T("返回值：") << MessageBox(NULL, _T("阁下果然是装逼高手"), _T("是在下输了"), MB_OKCANCEL | MB_ICONINFORMATION) << std::endl;

	system("pause");
	return 0;
}