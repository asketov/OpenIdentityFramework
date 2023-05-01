using System;
using OpenIdentityFramework.Services.Static.SyntaxValidation.Protocol;

namespace OpenIdentityFramework.Services.Static.SyntaxValidation;

public static class CodeVerifierSyntaxValidator
{
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
        return UnreservedCharSyntaxValidator.IsValid(value);
    }
}
