using System;
using System.Runtime.CompilerServices;

namespace OpenIdentityFramework.Services.Static.SyntaxValidation.Protocol;

public static class UnreservedCharSyntaxValidator
{
    private const char AlphaUpperMin = (char) 0x41;
    private const char AlphaUpperMax = (char) 0x5A;
    private const char AlphaLowerMin = (char) 0x61;
    private const char AlphaLowerMax = (char) 0x7A;

    private const char DigitMin = (char) 0x30;
    private const char DigitMax = (char) 0x39;

    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#appendix-A.18
        foreach (var ch in value)
        {
            if (!IsUnreserved(ch))
            {
                return false;
            }
        }

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsUnreserved(char ch)
    {
        return IsAlpha(ch) || IsDigit(ch) || IsAllowedNonAlphaOrDigit(ch);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsAlpha(char ch)
    {
        return ch is >= AlphaUpperMin and <= AlphaUpperMax or >= AlphaLowerMin and <= AlphaLowerMax;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsDigit(char ch)
    {
        return ch is >= DigitMin and <= DigitMax;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsAllowedNonAlphaOrDigit(char ch)
    {
        return ch is '-' or '.' or '_' or '~';
    }
}
