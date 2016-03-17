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
	virtual DWORD Call(CastArgFunc pCastArgFunc, LPVOID pStackTop, LPDWORD lpReturnValue, DWORD ArgSize, bool ReceiveReturnedValue) = 0;

protected:
	DWORD CallImpl(CallingConventionEnum CallingConvention, LPVOID pStackTop, LPVOID pArgs, LPDWORD lpReturnValue, DWORD ArgSize, DWORD ActualArgSize, bool ReceiveReturnedValue) const;
};

template <typename Func>
class InjectedFunction
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
		return *reinterpret_cast<void* const*>(reinterpret_cast<const void*>(&m_pFunc));
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

	DWORD Call(CastArgFunc pCastArgFunc, LPVOID pStackTop, LPDWORD lpReturnValue, DWORD ArgSize, bool ReceiveReturnedValue) override
	{
		constexpr uint tmpArgSize = FunctionInfo::ArgType::AlignedSize;
		const uint ActualArgSize = ReceiveReturnedValue ? tmpArgSize - calc_align(sizeof(typename GetType<FunctionInfo::ArgType::Count - 1, typename FunctionInfo::ArgType>::Type)) : tmpArgSize;
		byte tArg[tmpArgSize];

		if (pCastArgFunc)
		{
			pCastArgFunc(static_cast<const byte*>(pStackTop), tArg);
			return CallImpl(FunctionInfo::CallingConvention, pStackTop, tArg, lpReturnValue, ArgSize, ActualArgSize, ReceiveReturnedValue);
		}

		return CallImpl(FunctionInfo::CallingConvention, pStackTop, nullptr, lpReturnValue, ArgSize, ActualArgSize, ReceiveReturnedValue);
	}

private:
	Func m_pFunc;
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
		typedef std::conditional_t<FunctionAnalysis::FunctionAnalysis::CallingConvention != CallingConventionEnum::Thiscall, typename FunctionAnalysis::FunctionAnalysis::ArgType, typename AppendSequence<TypeSequence<typename FunctionAnalysis::FunctionAnalysis::ClassType>, typename FunctionAnalysis::FunctionAnalysis::ArgType>::Type> Func1Arg;
		typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis::ArgType Func2Arg;
		//static_assert(SequenceConvertible<Func2Arg, Func1Arg>::value, "Arguments between original and provided function are impatient.");
		static_assert(Func2Arg::Count <= Func1Arg::Count + 1u, "Too many arguments.");

		auto tRet = m_ReplacedFunc.first ? m_ReplacedFunc.first->GetFunctionPointer() : nullptr;
		m_ReplacedFunc.first = std::move(std::make_unique<InjectedFunction<Func>>(pFunc));
		m_ReplacedFunc.second = GetCastArgsStruct<Func1Arg, Func2Arg>::Type::Execute;

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
		typedef std::conditional_t<FunctionAnalysis::FunctionAnalysis::CallingConvention != CallingConventionEnum::Thiscall, typename FunctionAnalysis::FunctionAnalysis::ArgType, typename AppendSequence<TypeSequence<typename FunctionAnalysis::FunctionAnalysis::ClassType>, typename FunctionAnalysis::FunctionAnalysis::ArgType>::Type> Func1Arg;
		typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis::ArgType Func2Arg;
		static_assert(Func2Arg::Count <= Func1Arg::Count + 1u, "Too many arguments.");
		m_BeforeFunc.emplace_back(std::move(std::make_pair(std::make_unique<InjectedFunction<Func>>(pObject, pFunc), GetCastArgsStruct<Func1Arg, Func2Arg>::Type::Execute)));
	}

	template <typename Func>
	void RegisterAfter(Func pFunc)
	{
		RegisterAfter(nullptr, pFunc);
	}

	template <typename Func>
	void RegisterAfter(typename GetFunctionAnalysis<Func>::FunctionAnalysis::ClassType* pObject, Func pFunc)
	{
		typedef std::conditional_t<FunctionAnalysis::FunctionAnalysis::CallingConvention != CallingConventionEnum::Thiscall, typename FunctionAnalysis::FunctionAnalysis::ArgType, typename AppendSequence<TypeSequence<typename FunctionAnalysis::FunctionAnalysis::ClassType>, typename FunctionAnalysis::FunctionAnalysis::ArgType>::Type> Func1Arg;
		typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis::ArgType Func2Arg;
		static_assert(Func2Arg::Count <= Func1Arg::Count + 1u, "Too many arguments.");
		m_AfterFunc.emplace_back(std::move(std::make_pair(std::make_unique<InjectedFunction<Func>>(pObject, pFunc), GetCastArgsStruct<Func1Arg, Func2Arg>::Type::Execute)));
	}

	void Execute(LPVOID lpStackTop) override
	{
		DWORD tReturnValue = 0ul;
		bool tReceiveReturnedValue;
		const DWORD tArgSize = FunctionAnalysis::FunctionAnalysis::ArgType::AlignedSize;

		for (auto& Func : m_BeforeFunc)
		{
			Func.first->Call(Func.second, lpStackTop, &tReturnValue, tArgSize, false);
		}
		if (m_ReplacedFunc.first)
		{
			tReturnValue = m_ReplacedFunc.first->Call(m_ReplacedFunc.second, lpStackTop, &tReturnValue, tArgSize, false);
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
	std::pair<std::unique_ptr<Functor>, Functor::CastArgFunc> m_ReplacedFunc;
	std::vector<std::pair<std::unique_ptr<Functor>, Functor::CastArgFunc>> m_BeforeFunc;
	std::vector<std::pair<std::unique_ptr<Functor>, Functor::CastArgFunc>> m_AfterFunc;
};