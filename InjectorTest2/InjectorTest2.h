#pragma once
#include <d3d9.h>
#include <GenericInjector.h>

class InjectorTest2 final
	: public GenericInjector
{
public:
	InjectorTest2();
	~InjectorTest2();

	static InjectorTest2& GetInjector();

private:
	IDirect3D9* m_pDx9;
	IDirect3DDevice9* m_pDevice;

	void OnLoad() override;
	void OnUnload() override;

	void Dx9CreateHandler(UINT SDKVersion, IDirect3D9* pDx9);
	void Dx9CreateDeviceHandler(IDirect3D9* pDx9, UINT Adapter, D3DDEVTYPE DeviceType, HWND hFocusWindow, DWORD BehaviorFlags, D3DPRESENT_PARAMETERS* pPresentationParameters, IDirect3DDevice9** ppReturnedDeviceInterface, HRESULT RetCode);
};
