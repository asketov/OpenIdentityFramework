using System;
using OpenIdentityFramework.Services.Static.SyntaxValidation.Protocol;

namespace OpenIdentityFramework.Services.Static.SyntaxValidation;

public static class HttpBasicCredentialsSyntaxValidator
{
    // https://datatracker.ietf.org/doc/html/rfc7617#section-2
    // For credentials, the "token68" syntax defined in Section 2.1 of [RFC7235] is used.  The value is computed based on user-id and password as defined below.
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        return Token68SyntaxValidation.IsValid(value);
    }
}
