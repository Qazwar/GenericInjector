#include "InjectedFunction.h"

DWORD Functor::CallImpl(CallingConventionEnum CallingConvention, LPVOID pStackTop, LPVOID pArgs, LPVOID pOriginObject, LPDWORD lpReturnValue, DWORD ArgSize, DWORD ActualArgSize, bool ReceiveReturnedValue) const
{
	LPVOID pmemcpy = &memcpy;
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
		if (!pObject)
		{
			if (!pOriginObject)
			{
				return 0ul;
			}

			pObject = pOriginObject;
			pOriginObject = nullptr;
		}
		else
		{
			if (pOriginObject)
			{
				ActualArgSize -= sizeof pOriginObject;
			}
		}

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
				call pmemcpy;
				add esp, 12;

				cmp pOriginObject, 0;
				je NoObject1;
				push pOriginObject;
			NoObject1:

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
				call pmemcpy;
				add esp, 12;

				cmp pOriginObject, 0;
				je NoObject2;
				push pOriginObject;
			NoObject2:

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
	case CallingConventionEnum::Cdecl:
	{
		// ReSharper disable once CppEntityNeverUsed
		LPDWORD tpReturn;
		// Only replace function can have variable argument
		if (HasVariableArgument())
		{
			__asm
			{
				push ecx;
				push edx;

				sub esp, DefaultAlignBase * 2;
				lea ebx, [esp];

				mov esp, pStackTop;

				cmp pOriginObject, 0;
				je NoObject7;
				mov ebx, [esp - DefaultAlignBase];
				push pOriginObject;
			NoObject7:

				cmp pObject, 0;
				je NoThis5;
				lea eax, [ebx + DefaultAlignBase];
				mov eax, [esp];
				push pObject;
			NoThis5:

				mov eax, pFunc;
				call eax;

				mov tReturnValue, eax;

				cmp pOriginObject, 0;
				je NoObject8;
				lea eax, [esp - DefaultAlignBase];
				mov eax, [ebx];
			NoObject8:

				cmp pObject, 0;
				je NoThis6;
				mov esp, [ebx + DefaultAlignBase];
				jmp EndOfInject;

			NoThis6:
				lea esp, [ebx + DefaultAlignBase * 2];

			EndOfInject:
				pop ecx;
				pop edx;
			}
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
					mov tpReturn, eax;

					push ActualArgSize;
					push pArgs;
					push eax;
					call pmemcpy;
					add esp, 12;

					cmp pOriginObject, 0;
					je NoObject3;
					push pOriginObject;
				NoObject3:

					cmp pObject, 0;
					je NoThis1;
					push pObject;
				NoThis1:

					mov eax, pFunc;
					call eax;

					push ArgSize;
					push tpReturn;
					push pStackTop;
					call pmemcpy;
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
					sub esp, ActualArgSize;
					lea eax, [esp];
					mov tpReturn, eax;

					push ActualArgSize;
					push pArgs;
					push eax;
					call pmemcpy;
					add esp, 12;

					cmp pOriginObject, 0;
					je NoObject4;
					push pOriginObject;
				NoObject4:

					cmp pObject, 0;
					je NoThis2;
					push pObject;
				NoThis2:

					mov eax, pFunc;
					call eax;

					push ArgSize;
					push tpReturn;
					push pStackTop;
					call pmemcpy;
					add esp, 12;

					add esp, ActualArgSize;
					pop tReturnValue;

					pop edx;
					pop ecx;
				}
			}
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
				call pmemcpy;
				add esp, 12;

				cmp pOriginObject, 0;
				je NoObject5;
				push pOriginObject;
			NoObject5:

				cmp pObject, 0;
				je NoThis3;
				push pObject;
			NoThis3:

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
				call pmemcpy;
				add esp, 12;

				cmp pOriginObject, 0;
				je NoObject6;
				push pOriginObject;
			NoObject6:

				cmp pObject, 0;
				je NoThis4;
				push pObject;
			NoThis4:

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
