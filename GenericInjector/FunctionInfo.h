#pragma once
#include <type_traits>
#include <cstdint>

typedef uint32_t uint;
typedef uint8_t byte;

template <typename T1, typename T2>
struct IsSameTemplate
{
	constexpr static bool value = std::is_same<T1, T2>::value;
};

template <template <typename...> class Template, typename... T1, typename... T2>
struct IsSameTemplate<Template<T1...>, Template<T2...>>
{
	constexpr static bool value = true;
};

template <typename...>
struct TypeSequence;

template <typename T, typename... _Rest>
struct TypeSequence<T, _Rest...>
{
	typedef T Type;
	typedef TypeSequence<_Rest...> Rest;

	enum : uint
	{
		Count = 1 + sizeof...(_Rest),
		Size = sizeof(Type) + Rest::Size,
	};
};

template <>
struct TypeSequence<>
{
	enum : uint
	{
		Count = 0,
		Size = 0,
	};
};

template <uint Index, typename T>
struct GetType
{
	static_assert(Index < T::Count, "Out of range.");
	typedef typename GetType<Index - 1, typename T::Rest>::Type Type;
	typedef typename GetType<Index - 1, typename T::Rest>::TargetSequence TargetSequence;
};

template <typename T>
struct GetType<0u, T>
{
	typedef typename T::Type Type;
	typedef T TargetSequence;
};

template <typename T1, typename... T2>
struct AppendSequence;

template <typename... T1, typename... T2>
struct AppendSequence<TypeSequence<T1...>, TypeSequence<T2...>>
{
	typedef TypeSequence<T1..., T2...> Type;
};

template <typename... T, typename... Types>
struct AppendSequence<TypeSequence<T...>, Types...>
{
	typedef TypeSequence<T..., Types...> Type;
};

template <uint Count, typename T1, typename... T2>
struct SubtractSequenceHelper;

template <uint Count, typename... T, typename FirstType, typename... RestTypes>
struct SubtractSequenceHelper<Count, TypeSequence<T...>, FirstType, RestTypes...>
{
	typedef typename SubtractSequenceHelper<Count - 1u, typename AppendSequence<TypeSequence<T...>, FirstType>::Type, RestTypes...>::Type Type;
};

template <typename... T, typename... Types>
struct SubtractSequenceHelper<0u, TypeSequence<T...>, Types...>
{
	typedef TypeSequence<T...> Type;
};

template <typename T1, uint Count>
struct SubtractSequence;

template <typename... T1, uint Count>
struct SubtractSequence<TypeSequence<T1...>, Count>
{
	static_assert(sizeof...(T1) >= Count, "Count is too large.");
	typedef typename SubtractSequenceHelper<Count, TypeSequence<>, T1...>::Type Type;
};

template <typename T, uint Start, uint Count>
struct SubSequence
{
	static_assert(T::Count >= Start + Count, "Out of range.");
	typedef typename SubtractSequence<typename GetType<Start, T>::TargetSequence, Count>::Type Type;
};

template <typename T1, typename T2>
struct SequenceConvertible;

template <typename... T1, typename... T2>
struct SequenceConvertible<TypeSequence<T1...>, TypeSequence<T2...>>
{
	static constexpr bool value = std::is_convertible<typename TypeSequence<T1...>::Type, typename TypeSequence<T2...>::Type>::value && SequenceConvertible<typename TypeSequence<T1...>::Rest, typename TypeSequence<T2...>::Rest>::value;
};

template <>
struct SequenceConvertible<TypeSequence<>, TypeSequence<>>
{
	static constexpr bool value = true;
};

template <typename... T>
struct SequenceConvertible<TypeSequence<T...>, TypeSequence<>>
{
	static constexpr bool value = false;
};

template <typename... T>
struct SequenceConvertible<TypeSequence<>, TypeSequence<T...>>
{
	static constexpr bool value = false;
};

enum class CallingConventionEnum : byte
{
	Stdcall,
	Cdecl,
	Thiscall,
	Fastcall,
};

template <CallingConventionEnum _CallingConvention, bool _HasVariableArgument, typename _ClassType, typename Ret, typename... Arg>
struct AnalysisFunction
{
	static_assert(!_HasVariableArgument || _CallingConvention == CallingConventionEnum::Cdecl || _CallingConvention == CallingConventionEnum::Thiscall, "Only cdecl or thiscall function can have variable argument");

	static constexpr CallingConventionEnum CallingConvention = _CallingConvention;
	static constexpr bool HasVariableArgument = _HasVariableArgument;

	typedef typename std::conditional<CallingConvention == CallingConventionEnum::Thiscall, _ClassType, void>::type ClassType;

	typedef Ret ReturnType;
	typedef TypeSequence<Arg...> ArgType;
};

template <typename T>
struct GetFunctionAnalysis;

template <typename Ret, typename... Arg>
struct GetFunctionAnalysis<Ret(__stdcall*)(Arg...)>
{
	typedef AnalysisFunction<CallingConventionEnum::Stdcall, false, void, Ret, Arg...> FunctionAnalysis;
	typedef Ret(__stdcall* OriginalFunction)(Arg...);
};

template <typename Ret, typename... Arg>
struct GetFunctionAnalysis<Ret(__cdecl*)(Arg...)>
{
	typedef AnalysisFunction<CallingConventionEnum::Cdecl, false, void, Ret, Arg...> FunctionAnalysis;
	typedef Ret(__cdecl* OriginalFunction)(Arg...);
};

template <typename Ret, typename... Arg>
struct GetFunctionAnalysis<Ret(__cdecl*)(Arg..., ...)>
{
	typedef AnalysisFunction<CallingConventionEnum::Cdecl, true, void, Ret, Arg...> FunctionAnalysis;
	typedef Ret(__cdecl* OriginalFunction)(Arg..., ...);
};

template <typename ClassType, typename Ret, typename... Arg>
struct GetFunctionAnalysis<Ret(__thiscall ClassType::*)(Arg...)>
{
	typedef AnalysisFunction<CallingConventionEnum::Thiscall, false, ClassType, Ret, Arg...> FunctionAnalysis;
	typedef Ret(__thiscall ClassType::* OriginalFunction)(Arg...);
};

template <typename ClassType, typename Ret, typename... Arg>
struct GetFunctionAnalysis<Ret(__thiscall ClassType::*)(Arg...)const>
{
	typedef AnalysisFunction<CallingConventionEnum::Thiscall, false, const ClassType, Ret, Arg...> FunctionAnalysis;
	typedef Ret(__thiscall ClassType::* OriginalFunction)(Arg...)const;
};

template <typename ClassType, typename Ret, typename... Arg>
struct GetFunctionAnalysis<Ret(ClassType::*)(Arg..., ...)>
{
	typedef AnalysisFunction<CallingConventionEnum::Thiscall, true, ClassType, Ret, Arg...> FunctionAnalysis;
	typedef Ret(ClassType::* OriginalFunction)(Arg..., ...);
};

template <typename ClassType, typename Ret, typename... Arg>
struct GetFunctionAnalysis<Ret(ClassType::*)(Arg..., ...)const>
{
	typedef AnalysisFunction<CallingConventionEnum::Thiscall, true, const ClassType, Ret, Arg...> FunctionAnalysis;
	typedef Ret(ClassType::* OriginalFunction)(Arg..., ...)const;
};

template <typename Ret, typename... Arg>
struct GetFunctionAnalysis<Ret(__fastcall*)(Arg...)>
{
	typedef AnalysisFunction<CallingConventionEnum::Fastcall, false, void, Ret, Arg...> FunctionAnalysis;
	typedef Ret(__fastcall* OriginalFunction)(Arg...);
};