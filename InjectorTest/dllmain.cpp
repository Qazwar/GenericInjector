#include <GenericInjector.h>
#include <iostream>
#include <sstream>
#include <Windows.h>
#include <tchar.h>

// Inherit from GenericInjector to design your own injector
class InjectorTest final
	: public GenericInjector
{
public:
	InjectorTest()
	{
	}

	~InjectorTest()
	{
	}

	__declspec(noinline)
	void TestHook(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, double uType, int ReturnedValue)
	{
		// Output the argument of our injected function MessageBoxW passed by origin program
		std::wcout << hWnd << std::endl << lpText << std::endl << lpCaption << std::endl << uType << std::endl << ReturnedValue << std::endl;
		//GetPEPaser().GetImportFunctionAddress(_T(""), _T(""));
		// You can modify the returned value by simply assigning it
		// Turn off the optimization if you are using release configuration
		ReturnedValue = IDYES;

		// But you cannot modify arguments, lol
	}

	__declspec(noinline)
	static void PutC(int Code, int ReturnValue)
	{
		TCHAR tStr[2] {0};
		tStr[0] = static_cast<TCHAR>(Code);
		MessageBox(NULL, _T("Hooked"), tStr, MB_OK);
	}

	void OnLoad() override
	{
		try
		{
			std::wcout.imbue(std::locale("", LC_CTYPE));
			auto pFunc = GetPEPaser().GetImportFunctionAddress(_T("user32.dll"), _T("MessageBoxW"));
			std::cout << reinterpret_cast<LPVOID>(*pFunc) << std::endl << MessageBoxW << std::endl << std::endl;
			std::cout << GetPEPaser().GetImportFunctionAddress(_T("ucrtbased.dll"), _T("__stdio_common_vfprintf_s")) << std::endl << std::endl;
			auto pInjector = InjectImportTable<decltype(MessageBoxW)>(_T("user32.dll"), _T("MessageBoxW"));
			pInjector->RegisterAfter(this, &InjectorTest::TestHook);
			auto pInjector2 = InjectImportTable<decltype(putchar)>(_T("ucrtbased.dll"), _T("putchar"));
			pInjector2->RegisterAfter(PutC);
			pInjector2->Replace(nullptr);
			InjectImportTable<decltype(__stdio_common_vfprintf_s)>(_T("ucrtbased.dll"), _T("__stdio_common_vfprintf_s"));

			byte Pattern[] = "pause";
			auto pMem = reinterpret_cast<ptrdiff_t>(GetInstance()) + FindMemory(GetInstance(), Pattern, 1);

			constexpr byte Target[] = "cls";

			DWORD old;
			VirtualProtect(pMem, sizeof Target, PAGE_EXECUTE_READWRITE, &old);
			memcpy_s(pMem, sizeof Pattern, Target, sizeof Target);
			VirtualProtect(pMem, sizeof Target, old, &old);

			// nop
			//byte tmpCode[]{ 0x90, };
			// NOTE: Only usable on my machine, if you want to test it you should get the rva of the code you want to modify and replace arguments yourself.
			//InjectCode(GetInstance(), 0x16561, 0x47, tmpCode, 1);
			//ModifyCode(GetInstance(), 0x16561, 0x47, tmpCode, 1);
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
// If you don't use GenericInjetor in a dll project, you don't need to use InitInjector but you need to implement your own init function
InitInjector(InjectorTest::GetInjectorInstance())