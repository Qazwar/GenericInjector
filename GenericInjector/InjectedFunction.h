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
		CastArgs<typename T1::Rest, typename T2::Rest>::Execute(pOrigin + sizeof(typename T1::Type), pOut + sizeof(typename T2::Type));
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
	typedef void(*CastArgFunc)(const byte*, byte*);

	virtual ~Functor() = default;

	virtual LPVOID GetFunctionPointer() const noexcept = 0;
	virtual DWORD GetArgSize() const noexcept = 0;
	virtual DWORD GetArgCount() const noexcept = 0;
	virtual DWORD Call(CastArgFunc pCastArgFunc, LPVOID pStackTop, LPDWORD lpReturnValue, DWORD ArgSize, bool ReceiveReturnedValue) = 0;

protected:
	DWORD CallImpl(CallingConventionEnum CallingConvention, LPVOID pStackTop, LPVOID pArgs, LPDWORD lpReturnValue, DWORD ArgSize, bool ReceiveReturnedValue) const;
};

template <typename Func>
class InjectedFunction
	: public Functor
{
public:
	typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis FunctionInfo;

	// ReSharper disable once CppNonExplicitConvertingConstructor
	InjectedFunction(Func pFunc)
		: m_pFunc(pFunc)
	{
	}

	LPVOID GetFunctionPointer() const noexcept override
	{
		return m_pFunc;
	}

	DWORD GetArgSize() const noexcept override
	{
		return FunctionInfo::ArgType::Size;
	}

	DWORD GetArgCount() const noexcept override
	{
		return FunctionInfo::ArgType::Count;
	}

	DWORD Call(CastArgFunc pCastArgFunc, LPVOID pStackTop, LPDWORD lpReturnValue, DWORD ArgSize, bool ReceiveReturnedValue) override
	{
		byte tArg[FunctionInfo::ArgType::Size];

		if (pCastArgFunc)
		{
			pCastArgFunc(static_cast<const byte*>(pStackTop), tArg);
			return CallImpl(FunctionInfo::CallingConvention, pStackTop, tArg, lpReturnValue, ArgSize, ReceiveReturnedValue);
		}

		return CallImpl(FunctionInfo::CallingConvention, pStackTop, nullptr, lpReturnValue, ArgSize, ReceiveReturnedValue);
	}

private:
	Func m_pFunc;
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

struct FunctionInjectorBase
{
	virtual ~FunctionInjectorBase() = default;

	virtual void Execute(LPVOID lpStackTop) = 0;
};

template <typename FunctionPrototype>
class FunctionInjector final
	: public FunctionInjectorBase
{
	friend class GenericInjector;
public:
	typedef GetFunctionAnalysis<FunctionPrototype> FunctionAnalysis;

	FunctionInjector() = default;

	template <typename Func>
	// ReSharper disable once CppNonExplicitConvertingConstructor
	FunctionInjector(Func pFunc)
		: m_ReplacedFunc(std::move(std::make_unique<InjectedFunction<Func>>(pFunc)))
	{
	}

	~FunctionInjector() = default;

	template <typename Func>
	LPVOID Replace(Func pFunc)
	{
		typedef typename FunctionAnalysis::FunctionAnalysis::ArgType Func1Arg;
		typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis::ArgType Func2Arg;
		static_assert(SequenceConvertible<Func2Arg, Func1Arg>::value, "Arguments between original and provided function are impatient.");

		auto tRet = m_ReplacedFunc ? m_ReplacedFunc->GetFunctionPointer() : nullptr;
		m_ReplacedFunc = std::move(std::make_unique<InjectedFunction<Func>>(pFunc));

		return tRet;
	}

	LPVOID Replace(nullptr_t)
	{
		auto tRet = m_ReplacedFunc ? m_ReplacedFunc->GetFunctionPointer() : nullptr;
		m_ReplacedFunc.reset();
		return tRet;
	}

	template <typename Func>
	void RegisterBefore(Func pFunc)
	{
		typedef typename FunctionAnalysis::FunctionAnalysis::ArgType Func1Arg;
		typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis::ArgType Func2Arg;
		static_assert(Func2Arg::Count <= Func1Arg::Count + 1u, "Too many arguments.");
		m_BeforeFunc.emplace_back(std::move(std::make_pair(std::make_unique<InjectedFunction<Func>>(pFunc), GetCastArgsStruct<Func1Arg, Func2Arg>::Type::Execute)));
	}

	template <typename Func>
	void RegisterAfter(Func pFunc)
	{
		typedef typename FunctionAnalysis::FunctionAnalysis::ArgType Func1Arg;
		typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis::ArgType Func2Arg;
		static_assert(Func2Arg::Count <= Func1Arg::Count + 1u, "Too many arguments.");
		m_AfterFunc.emplace_back(std::move(std::make_pair(std::make_unique<InjectedFunction<Func>>(pFunc), GetCastArgsStruct<Func1Arg, Func2Arg>::Type::Execute)));
	}

	void Execute(LPVOID lpStackTop) override
	{
		DWORD tReturnValue = 0ul;
		bool tReceiveReturnedValue;
		const DWORD tArgSize = m_ReplacedFunc ? m_ReplacedFunc->GetArgSize() : 0ul;

		for (auto& Func : m_BeforeFunc)
		{
			Func.first->Call(Func.second, lpStackTop, &tReturnValue, tArgSize, false);
		}
		if (m_ReplacedFunc)
		{
			tReturnValue = m_ReplacedFunc->Call(nullptr, lpStackTop, &tReturnValue, tArgSize, false);
		}
		__asm mov tReturnValue, eax;
		
		for (auto& Func : m_AfterFunc)
		{
			tReceiveReturnedValue = Func.first->GetArgCount() == FunctionAnalysis::FunctionAnalysis::ArgType::Count + 1;
			tReturnValue = Func.first->Call(Func.second, lpStackTop, &tReturnValue, tArgSize, tReceiveReturnedValue);
		}
		__asm mov eax, tReturnValue;
	}

private:
	std::unique_ptr<Functor> m_ReplacedFunc;
	std::vector<std::pair<std::unique_ptr<Functor>, Functor::CastArgFunc>> m_BeforeFunc;
	std::vector<std::pair<std::unique_ptr<Functor>, Functor::CastArgFunc>> m_AfterFunc;
};