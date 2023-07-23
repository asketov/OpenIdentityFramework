using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultSupported
{
    public static readonly IReadOnlySet<string> AuthenticationMethods = new HashSet<string>(StringComparer.Ordinal)
    {
        DefaultClientAuthenticationMethods.ClientSecretBasic,
        DefaultClientAuthenticationMethods.None,
        DefaultClientAuthenticationMethods.ClientSecretPost
    };
}
