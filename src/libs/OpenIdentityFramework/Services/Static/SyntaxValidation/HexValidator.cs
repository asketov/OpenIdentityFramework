using System;
using System.Runtime.CompilerServices;

namespace OpenIdentityFramework.Services.Static.SyntaxValidation;

public static class HexValidator
{
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        if (value.Length == 0)
        {
            return true;
        }

        if ((uint) value.Length % 2 != 0)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (!IsDigit(ch) && !IsUppercaseAlpha(ch) && !IsLowercaseAlpha(ch))
            {
                return false;
            }
        }

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsDigit(char ch)
    {
        return ch is >= '0' and <= '9';
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsUppercaseAlpha(char ch)
    {
        return ch is >= 'A' and <= 'Z';
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsLowercaseAlpha(char ch)
    {
        return ch is >= 'a' and <= 'z';
    }
}
