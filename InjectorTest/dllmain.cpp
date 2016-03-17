#include "stdafx.h"
#include <GenericInjector.h>
#include <iostream>
#include <sstream>

// Extends from GenericInjector to design your own injector
class InjectorTest final
	: public GenericInjector
{
public:
	InjectorTest()
	{
	}

	~InjectorTest() override
	{
	}

	__declspec(noinline)
	void TestHook(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, unsigned short uType, int iReturnedValue)
	{
		// Output the argument of our injected function MessageBoxW passed by origin program
		std::wcout << hWnd << std::endl << lpText << std::endl << lpCaption << std::endl << uType << std::endl << iReturnedValue << std::endl;
		// You can modify the returned value by simply assigning it
		// Turn off the optimization if you are using release configuration
		iReturnedValue = IDYES;

		// But you cannot modify arguments, lol
	}

	void OnLoad() override
	{
		try
		{
			std::wcout.imbue(std::locale("", LC_CTYPE));
			auto pFunc = GetPEPaser().GetImportFunctionAddress(_T("user32.dll"), _T("MessageBoxW"));
			std::cout << reinterpret_cast<LPVOID>(*pFunc) << std::endl << MessageBoxW << std::endl << std::endl;
			auto pInjector = InjectImportTable<decltype(&MessageBoxW)>(_T("user32.dll"), _T("MessageBoxW"));
			pInjector->RegisterAfter(this, &InjectorTest::TestHook);
		}
		catch (std::system_error& sysex)
		{
			std::stringstream ss;
			ss << "what: " << sysex.what() << ", code:" << sysex.code();

			MessageBoxA(NULL, ss.str().c_str(), "Unhandled exception caught", MB_OK | MB_ICONERROR);
			std::cerr << ss.str() << std::endl;
			exit(EXIT_FAILURE);
		}
		catch (std::exception& ex)
		{
			MessageBoxA(NULL, ex.what(), "Unhandled exception caught", MB_OK | MB_ICONERROR);
			std::cerr << ex.what() << std::endl;
			exit(EXIT_FAILURE);
		}
	}

	void OnUnload() override
	{
	}

	static InjectorTest& GetInjectorInstance()
	{
		static InjectorTest Instance;
		return Instance;
	}

private:

};

// Implement our injector, you can also use global variant
// DO NOT TRY TO IMPLEMENT OTHER DllMain!
InitInjector(InjectorTest::GetInjectorInstance())