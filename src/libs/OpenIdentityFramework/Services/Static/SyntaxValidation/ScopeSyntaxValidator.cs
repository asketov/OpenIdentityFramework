using System;
using OpenIdentityFramework.Services.Static.SyntaxValidation.Protocol;

namespace OpenIdentityFramework.Services.Static.SyntaxValidation;

public static class ScopeSyntaxValidator
{
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#appendix-A.4
        return NqCharSyntaxValidator.IsValid(value);
    }
}
