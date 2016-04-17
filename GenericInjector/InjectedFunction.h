#pragma once
#include "FunctionInfo.h"
#include <memory>
#include <vector>

#define NOMINMAX 1
#include <Windows.h>

template <typename T1, typename T2>
struct CastArgs
{
	static_assert(IsSameTemplate<T1, T2>::value && IsSameTemplate<T1, TypeSequence<>>::value, "T1 and T2 should be TypeSequence.");
	static_assert(SequenceConvertible<T1, T2>::value, "T1 and T2 should be convertible.");

	static void Execute(const byte* pOrigin, byte* pOut)
	{
		*reinterpret_cast<typename T2::Type*>(pOut) = static_cast<typename T2::Type>(*reinterpret_cast<const typename T1::Type*>(pOrigin));
		CastArgs<typename T1::Rest, typename T2::Rest>::Execute(pOrigin + calc_align(sizeof(typename T1::Type)), pOut + calc_align(sizeof(typename T2::Type)));
	}
};

template <>
struct CastArgs<TypeSequence<>, TypeSequence<>>
{
	static void Execute(const byte* /*pOrigin*/, byte* /*pOut*/)
	{
	}
};

struct Functor
{
	typedef void (*CastArgFunc)(const byte*, byte*);

	virtual ~Functor() = default;

	virtual bool HasVariableArgument() const noexcept = 0;

	virtual LPVOID GetFunctionPointer() const noexcept = 0;
	virtual LPVOID GetObjectPointer() const noexcept = 0;
	virtual DWORD GetArgSize() const noexcept = 0;
	virtual DWORD GetArgCount() const noexcept = 0;
	virtual DWORD Call(CastArgFunc pCastArgFunc, LPVOID pStackTop, LPVOID pObject, LPDWORD lpReturnValue, DWORD ArgSize, bool ReceiveReturnedValue) = 0;

protected:
	DWORD CallImpl(CallingConventionEnum CallingConvention, LPVOID pStackTop, LPVOID pArgs, LPVOID pOriginObject, LPDWORD lpReturnValue, DWORD ArgSize, DWORD ActualArgSize, bool ReceiveReturnedValue) const;
};

template <typename Func>
class InjectedFunction final
	: public Functor
{
public:
	typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis FunctionInfo;

	// ReSharper disable once CppNonExplicitConvertingConstructor
	InjectedFunction(Func pFunc)
		: m_pFunc(pFunc),
		m_pObject(nullptr)
	{
	}

	InjectedFunction(typename FunctionInfo::ClassType* pObject, Func pFunc)
		: m_pFunc(pFunc),
		m_pObject(pObject)
	{
	}

	~InjectedFunction() = default;

	bool HasVariableArgument() const noexcept override
	{
		return FunctionInfo::HasVariableArgument;
	}

	LPVOID GetFunctionPointer() const noexcept override
	{
		return m_RawPointer;
	}

	LPVOID GetObjectPointer() const noexcept override
	{
		return m_pObject;
	}

	DWORD GetArgSize() const noexcept override
	{
		return FunctionInfo::ArgType::Size;
	}

	DWORD GetArgCount() const noexcept override
	{
		return FunctionInfo::ArgType::Count;
	}

	DWORD Call(CastArgFunc pCastArgFunc, LPVOID pStackTop, LPVOID pObject, LPDWORD lpReturnValue, DWORD ArgSize, bool ReceiveReturnedValue) override
	{
		constexpr uint tmpArgSize = FunctionInfo::ArgType::AlignedSize;
		// may include this
		const uint ActualArgSize = ReceiveReturnedValue ? tmpArgSize - calc_align(sizeof(typename GetType<FunctionInfo::ArgType::Count - 1, typename FunctionInfo::ArgType>::Type)) : tmpArgSize;
		byte tArg[tmpArgSize];

		if (pCastArgFunc)
		{
			pCastArgFunc(static_cast<const byte*>(pStackTop), tArg);
			return CallImpl(FunctionInfo::CallingConvention, pStackTop, tArg, pObject, lpReturnValue, ArgSize, ActualArgSize, ReceiveReturnedValue);
		}

		if (ReceiveReturnedValue)
		{
			// Error
			return 0ul;
		}
		return CallImpl(FunctionInfo::CallingConvention, pStackTop, nullptr, pObject, lpReturnValue, ArgSize, ActualArgSize, false);
	}

private:
	union
	{
		Func m_pFunc;
		void* m_RawPointer;
	};
	
	typename FunctionInfo::ClassType* m_pObject;
};

template <typename Func>
auto MakeInjectedFunction(Func pFunc)
{
	return InjectedFunction<Func>(pFunc);
}

template <bool T1Bigger, typename T1, typename T2>
struct GetCastArgsStructHelper
{
	typedef CastArgs<T1, typename SubSequence<T2, 0u, T1::Count>::Type> Type;
};

template <typename T1, typename T2>
struct GetCastArgsStructHelper<true, T1, T2>
{
	typedef CastArgs<typename SubSequence<T1, 0u, T2::Count>::Type, T2> Type;
};

template <typename T1, typename T2>
struct GetCastArgsStruct
{
	typedef typename GetCastArgsStructHelper<T1::Count >= T2::Count, T1, T2>::Type Type;
};

template <typename... Arg>
struct GetCastArgsStruct<TypeSequence<Arg...>, TypeSequence<Arg...>>
{
	struct Type
	{
		static constexpr Functor::CastArgFunc Execute = nullptr;
	};
};

template <bool Condition, typename T>
struct PopFrontIf
{
	typedef typename GetType<1u, T>::TargetSequence Type;
};

template <typename T>
struct PopFrontIf<false, T>
{
	typedef T Type;
};

template <bool Condition, typename T>
struct PopBackIf
{
	typedef typename SubSequence<T, 0u, T::Size - 1>::Type Type;
};

template <typename T>
struct PopBackIf<false, T>
{
	typedef T Type;
};

struct FunctionInjectorBase
{
	virtual ~FunctionInjectorBase() = default;

	virtual LPVOID GetFunctionPointer() const noexcept = 0;
	virtual void Execute(DWORD dwECX, LPVOID lpStackTop) = 0;
};

template <typename FunctionPrototype>
class FunctionInjector final
	: public FunctionInjectorBase
{
	friend class GenericInjector;
public:
	typedef typename GetFunctionAnalysis<FunctionPrototype>::FunctionAnalysis FunctionAnalysis;

	FunctionInjector() = default;

	template <typename Func>
	// ReSharper disable once CppNonExplicitConvertingConstructor
	FunctionInjector(Func pFunc)
		: m_ReplacedFunc(std::move(std::make_unique<InjectedFunction<Func>>(pFunc)))
	{
		m_OriginalFunction.OriginalFunctionPointer = pFunc;
	}

	~FunctionInjector() = default;

	template <typename Func>
	LPVOID Replace(Func pFunc)
	{
		typedef std::conditional_t<std::is_same<typename FunctionAnalysis::ClassType, void>::value, typename FunctionAnalysis::ArgType, typename AppendSequence<TypeSequence<typename FunctionAnalysis::ClassType>, typename FunctionAnalysis::ArgType>::Type> Func1Arg;
		typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis::ArgType Func2Arg;
		typedef typename FunctionAnalysis::ArgType RealFunc1Arg;
		typedef typename PopFrontIf<!std::is_same<typename FunctionAnalysis::ClassType, void>::value, Func2Arg>::Type RealFunc2Arg;
		static_assert(std::is_same<typename FunctionAnalysis::ClassType, void>::value || std::is_convertible<std::add_pointer_t<typename FunctionAnalysis::ClassType>, typename Func2Arg::Type>::value, "Original class type cannot be converted to target class.");
		static_assert(RealFunc2Arg::Count <= RealFunc1Arg::Count, "Too many arguments.");
		static_assert(!(FunctionAnalysis::HasVariableArgument ^ GetFunctionAnalysis<Func>::HasVariableArgument), "Replace function should have variable argument if original function has variable argument.");

		auto tRet = m_ReplacedFunc.first ? m_ReplacedFunc.first->GetFunctionPointer() : nullptr;
		m_ReplacedFunc.first = std::move(std::make_unique<InjectedFunction<Func>>(pFunc));
		m_ReplacedFunc.second = GetCastArgsStruct<RealFunc1Arg, RealFunc2Arg>::Type::Execute;

		return tRet;
	}

	LPVOID Replace(nullptr_t)
	{
		auto tRet = m_ReplacedFunc.first ? m_ReplacedFunc.first->GetFunctionPointer() : nullptr;
		m_ReplacedFunc.first.reset();
		m_ReplacedFunc.second = nullptr;
		return tRet;
	}

	template <typename Func>
	void RegisterBefore(Func pFunc)
	{
		RegisterBefore(nullptr, pFunc);
	}

	template <typename Func>
	void RegisterBefore(typename GetFunctionAnalysis<Func>::FunctionAnalysis::ClassType* pObject, Func pFunc)
	{
		typedef std::conditional_t<std::is_same<typename FunctionAnalysis::ClassType, void>::value, typename FunctionAnalysis::ArgType, typename AppendSequence<TypeSequence<typename FunctionAnalysis::ClassType>, typename FunctionAnalysis::ArgType>::Type> Func1Arg;
		typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis::ArgType Func2Arg;
		typedef typename FunctionAnalysis::ArgType RealFunc1Arg;
		typedef typename PopBackIf<FunctionAnalysis::HasVariableArgument && std::is_same<typename GetType<Func2Arg::Count - 1, Func2Arg>::Type, va_list>::value, typename PopFrontIf<!std::is_same<typename FunctionAnalysis::ClassType, void>::value, Func2Arg>::Type>::Type RealFunc2Arg;
		static_assert(std::is_same<typename FunctionAnalysis::ClassType, void>::value || std::is_convertible<std::add_pointer_t<typename FunctionAnalysis::ClassType>, typename Func2Arg::Type>::value, "Original class type cannot be converted to target class.");
		static_assert(RealFunc2Arg::Count <= RealFunc1Arg::Count + 1u, "Too many arguments.");
		static_assert(!GetFunctionAnalysis<Func>::FunctionAnalysis::HasVariableArgument, "Hook function cannot have variable argument.");
		m_BeforeFunc.emplace_back(std::make_pair(std::make_unique<InjectedFunction<Func>>(pObject, pFunc), GetCastArgsStruct<RealFunc1Arg, RealFunc2Arg>::Type::Execute));
	}

	template <typename Func>
	void RegisterAfter(Func pFunc)
	{
		RegisterAfter(nullptr, pFunc);
	}

	template <typename Func>
	void RegisterAfter(typename GetFunctionAnalysis<Func>::FunctionAnalysis::ClassType* pObject, Func pFunc)
	{
		typedef std::conditional_t<std::is_same<typename FunctionAnalysis::ClassType, void>::value, typename FunctionAnalysis::ArgType, typename AppendSequence<TypeSequence<typename FunctionAnalysis::ClassType>, typename FunctionAnalysis::ArgType>::Type> Func1Arg;
		typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis::ArgType Func2Arg;
		typedef typename FunctionAnalysis::ArgType RealFunc1Arg;
		typedef typename PopBackIf<FunctionAnalysis::HasVariableArgument && std::is_same<typename GetType<Func2Arg::Count - 1, Func2Arg>::Type, va_list>::value, typename PopFrontIf<!std::is_same<typename FunctionAnalysis::ClassType, void>::value, Func2Arg>::Type>::Type RealFunc2Arg;
		static_assert(std::is_same<typename FunctionAnalysis::ClassType, void>::value || std::is_convertible<std::add_pointer_t<typename FunctionAnalysis::ClassType>, typename Func2Arg::Type>::value, "Original class type cannot be converted to target class.");
		static_assert(RealFunc2Arg::Count <= RealFunc1Arg::Count + 1u, "Too many arguments.");
		static_assert(!GetFunctionAnalysis<Func>::FunctionAnalysis::HasVariableArgument, "Hook function cannot have variable argument.");
		m_AfterFunc.emplace_back(std::make_pair(std::make_unique<InjectedFunction<Func>>(pObject, pFunc), GetCastArgsStruct<RealFunc1Arg, RealFunc2Arg>::Type::Execute));
	}

	LPVOID GetFunctionPointer() const noexcept override
	{
		return m_OriginalFunction.RawPointer;
	}

	void Execute(DWORD dwECX, LPVOID lpStackTop) override
	{
		LPVOID pObject = nullptr;
		if (!std::is_same<typename FunctionAnalysis::ClassType, void>::value)
		{
			if (FunctionAnalysis::CallingConvention == CallingConventionEnum::Thiscall)
			{
				pObject = reinterpret_cast<LPVOID>(dwECX);
			}
			else
			{
				pObject = *reinterpret_cast<LPVOID*>(lpStackTop);
				lpStackTop = static_cast<byte*>(lpStackTop) + sizeof(LPVOID);
			}

			if (!pObject)
			{
				// Error
				__asm xor eax, eax;
				return;
			}
		}

		DWORD tReturnValue = 0ul;
		bool tReceiveReturnedValue;
		constexpr auto tArgSize = FunctionAnalysis::ArgType::AlignedSize;

		for (auto& Func : m_BeforeFunc)
		{
			Func.first->Call(Func.second, lpStackTop, pObject, &tReturnValue, tArgSize, false);
		}
		if (m_ReplacedFunc.first)
		{
			tReturnValue = m_ReplacedFunc.first->Call(m_ReplacedFunc.second, lpStackTop, pObject, &tReturnValue, tArgSize, false);
		}
		else
		{
			__asm xor eax, eax;
		}
		__asm mov tReturnValue, eax;
		
		for (auto& Func : m_AfterFunc)
		{
			tReceiveReturnedValue = Func.first->GetArgCount() == FunctionAnalysis::ArgType::Count + (std::is_same<typename FunctionAnalysis::ClassType, void>::value ? 0 : 1) + 1;
			tReturnValue = Func.first->Call(Func.second, lpStackTop, pObject, &tReturnValue, tArgSize, tReceiveReturnedValue);
		}
		__asm mov eax, tReturnValue;
	}

private:
	union
	{
		FunctionPrototype OriginalFunctionPointer;
		LPVOID RawPointer;
	} m_OriginalFunction;

	std::pair<std::unique_ptr<Functor>, Functor::CastArgFunc> m_ReplacedFunc;
	std::vector<std::pair<std::unique_ptr<Functor>, Functor::CastArgFunc>> m_BeforeFunc;
	std::vector<std::pair<std::unique_ptr<Functor>, Functor::CastArgFunc>> m_AfterFunc;
};