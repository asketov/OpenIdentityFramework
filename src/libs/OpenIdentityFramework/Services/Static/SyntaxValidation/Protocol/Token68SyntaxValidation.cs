using System;

namespace OpenIdentityFramework.Services.Static.SyntaxValidation.Protocol;

public static class Token68SyntaxValidation
{
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://datatracker.ietf.org/doc/html/rfc7235#section-2.1
        foreach (var ch in value)
        {
            if (ch is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.' or '_' or '~' or '+' or '/' or '='))
            {
                return false;
            }
        }

        // The value can ends with multiple "=".
        var equalsSymbolWasFound = false;
        foreach (var ch in value)
        {
            if (equalsSymbolWasFound && ch != '=')
            {
                return false;
            }

            if (ch == '=')
            {
                equalsSymbolWasFound = true;
            }
        }

        return true;
    }
}
