using System;

namespace OpenIdentityFramework.Services.Static.SyntaxValidation.Protocol;

public static class NqCharSyntaxValidator
{
    private const char SeparateValue = (char) 0x21;
    private const char Range1Min = (char) 0x23;
    private const char Range1Max = (char) 0x5B;
    private const char Range2Min = (char) 0x5D;
    private const char Range2Max = (char) 0x5B;

    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A
        foreach (var ch in value)
        {
            if (ch is not (SeparateValue or >= Range1Min and <= Range1Max or >= Range2Min and <= Range2Max))
            {
                return false;
            }
        }

        return true;
    }
}
