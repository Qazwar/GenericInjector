#include "InjectedFunction.h"

DWORD Functor::CallImpl(CallingConventionEnum CallingConvention, LPVOID pStackTop, LPVOID pArgs, LPDWORD lpReturnValue, DWORD ArgSize, bool ReceiveReturnedValue) const
{
	LPVOID pFunc = GetFunctionPointer();
	if (!pFunc)
		return 0ul;

	if (!pArgs)
	{
		pArgs = pStackTop;
	}

	DWORD tReturnValue = 0ul;
	DWORD ActualArgSize = GetArgSize();
	if (ReceiveReturnedValue)
	{
		ActualArgSize -= sizeof(DWORD);
	}
	
	switch (CallingConvention)
	{
	case CallingConventionEnum::Cdecl:
	{
		// ReSharper disable once CppEntityNeverUsed
		LPDWORD tpReturn;
		if (!ReceiveReturnedValue)
		{
			__asm
			{
				push ecx;
				push edx;

				sub esp, ActualArgSize;
				lea eax, [esp];
				mov tpReturn, eax;

				push ActualArgSize;
				push pArgs;
				push eax;
				call memcpy;
				add esp, 12;

				mov eax, pFunc;
				call eax;

				push ActualArgSize;
				push tpReturn;
				push pStackTop;
				call memcpy;
				add esp, 12;

				mov tReturnValue, eax;
				add esp, ActualArgSize;

				pop edx;
				pop ecx;
			}
		}
		else
		{
			tReturnValue = *lpReturnValue;
			__asm
			{
				push ecx;
				push edx;

				push tReturnValue;
				sub esp, ArgSize;
				lea eax, [esp];
				mov tpReturn, eax;

				push ArgSize;
				push pArgs;
				push eax;
				call memcpy;
				add esp, 12;

				mov eax, pFunc;
				call eax;

				push ArgSize;
				push tpReturn;
				push pStackTop;
				call memcpy;
				add esp, 12;

				add esp, ArgSize;
				pop tReturnValue;

				pop edx;
				pop ecx;
			}
		}

		return tReturnValue;
	}
	case CallingConventionEnum::Thiscall:
		ActualArgSize += sizeof(LPVOID);
	case CallingConventionEnum::Stdcall:
		if (!ReceiveReturnedValue)
		{
			__asm
			{
				push ecx;
				push edx;

				sub esp, ActualArgSize;
				lea eax, [esp];

				push ActualArgSize;
				push pArgs;
				push eax;
				call memcpy;
				add esp, 12;

				mov eax, pFunc;
				call eax;
				mov tReturnValue, eax;

				pop edx;
				pop ecx;
			}
		}
		else
		{
			tReturnValue = *lpReturnValue;
			__asm
			{
				push ecx;
				push edx;

				push tReturnValue;
				sub esp, ActualArgSize;
				lea eax, [esp];

				push ActualArgSize;
				push pArgs;
				push eax;
				call memcpy;
				add esp, 12;

				mov eax, pFunc;
				call eax;
				mov tReturnValue, eax;

				pop edx;
				pop ecx;
			}
		}

		return tReturnValue;
	default:
		break;
	}

	return 0ul;
}
