#include "InjectorTest2.h"
#include <iostream>
#include <sstream>
#include <tchar.h>

InjectorTest2::InjectorTest2()
	: m_pDx9(nullptr), m_pDevice(nullptr)
{
}

InjectorTest2::~InjectorTest2()
{
}

InjectorTest2& InjectorTest2::GetInjector()
{
	static InjectorTest2 Instance;

	return Instance;
}

void InjectorTest2::OnLoad()
{
	try
	{
		auto pInjector = InjectImportTable<decltype(Direct3DCreate9)>(_T("d3d9.dll"), _T("Direct3DCreate9"));
		pInjector->RegisterAfter(this, &InjectorTest2::Dx9CreateHandler);
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

void InjectorTest2::OnUnload()
{
}

void InjectorTest2::Dx9CreateHandler(UINT /*SDKVersion*/, IDirect3D9* pDx9)
{
	if (pDx9 != nullptr)
	{
		m_pDx9 = pDx9;
		InjectVirtualTable<decltype(&IDirect3D9::CreateDevice)>(m_pDx9, 16)->RegisterAfter(this, &InjectorTest2::Dx9CreateDeviceHandler);
	}
}

void InjectorTest2::Dx9CreateDeviceHandler(IDirect3D9* pDx9, UINT Adapter, D3DDEVTYPE DeviceType, HWND hFocusWindow, DWORD BehaviorFlags, D3DPRESENT_PARAMETERS* pPresentationParameters, IDirect3DDevice9** ppReturnedDeviceInterface, HRESULT RetCode)
{
	if (pDx9 == m_pDx9 && RetCode == S_OK && ppReturnedDeviceInterface != nullptr && *ppReturnedDeviceInterface != nullptr)
	{
		m_pDevice = *ppReturnedDeviceInterface;
		std::stringstream ss;
		ss << m_pDx9 << "@" << m_pDevice;
		MessageBoxA(NULL, ss.str().c_str(), "Dx Got", MB_OK);
	}
}
