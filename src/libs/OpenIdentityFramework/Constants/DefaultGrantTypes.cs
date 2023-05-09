using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultGrantTypes
{
    public const string AuthorizationCode = "authorization_code";
    public const string ClientCredentials = "client_credentials";
    public const string RefreshToken = "refresh_token";

    public static readonly IReadOnlySet<string> Supported = new HashSet<string>
    {
        AuthorizationCode,
        ClientCredentials,
        RefreshToken
    };
}
