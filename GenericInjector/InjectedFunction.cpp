#include "InjectedFunction.h"

DWORD Functor::CallImpl(CallingConventionEnum CallingConvention, LPVOID pStackTop, LPVOID pArgs, LPDWORD lpReturnValue, DWORD ArgSize, DWORD ActualArgSize, bool ReceiveReturnedValue) const
{
	LPVOID pFunc = GetFunctionPointer();
	if (!pFunc)
		return 0ul;

	LPVOID pObject = GetObjectPointer();

	if (!pArgs)
	{
		pArgs = pStackTop;
	}

	DWORD tReturnValue = 0ul;

	switch (CallingConvention)
	{
	case CallingConventionEnum::Thiscall:
		// TODO: implement passing variable argument
		if (HasVariableArgument())
		{
			LPDWORD tpReturn;
			if (!ReceiveReturnedValue)
			{
				__asm
				{
					push ecx;
					push edx;

					push pObject;
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
					push pObject;
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
		else
		{
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
					mov ecx, pObject;
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
					mov ecx, pObject;
					call eax;
					mov eax, [esp - 4];
					mov tReturnValue, eax;

					pop edx;
					pop ecx;
				}
			}

			return tReturnValue;
		}
		break;
	case CallingConventionEnum::Cdecl:
	{
		// ReSharper disable once CppEntityNeverUsed
		LPDWORD tpReturn;
		if (HasVariableArgument())
		{
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
		}
		else
		{
			// TODO: implement passing variable argument
		}

		return tReturnValue;
	}
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
				mov eax, [esp - 4];
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
