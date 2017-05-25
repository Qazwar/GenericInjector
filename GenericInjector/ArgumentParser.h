#pragma once
#include "InjectedFunction.h"

template <typename Func>
class ArgumentParser final
{
	template <typename Seq, size_t I>
	struct Get;

	template <typename... T, size_t I>
	struct Get<TypeSequence<T...>, I>
	{
		typedef TypeSequence<T...> seq;
		typedef GetType<I, seq> type;

		static type Impl(LPVOID pArg)
		{
			return *reinterpret_cast<type*>(pArg + SubSequence<seq, 0, I>::Type::AlignedSize);
		}
	};

public:
	typedef typename GetFunctionAnalysis<Func>::FunctionAnalysis FuncInfo;

	explicit ArgumentParser(LPVOID pArgs)
		: ArgumentParser(pArgs, typename std::make_index_sequence<FuncInfo::ArgType::Count>::type{})
	{
	}

	template <size_t I>
	decltype(auto) GetArg()
	{
		return std::get<I>(m_Args);
	}

	template <size_t I>
	decltype(auto) GetArg() const
	{
		return std::get<I>(m_Args);
	}

private:
	typename CastToTuple<typename FuncInfo::ArgType>::Type m_Args;

	template <size_t... I>
	ArgumentParser(LPVOID pArgs, std::index_sequence<I...>)
		: m_Args{ Get<typename FuncInfo::ArgType, I>::Impl(pArgs)... }
	{
	}
};
