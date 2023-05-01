using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultTokenTypes
{
    public const string IdToken = "id_token";
    public const string AccessToken = "access_token";
    public const string RefreshToken = "refresh_token";

    public static readonly IReadOnlySet<string> OAuth = new HashSet<string>(StringComparer.Ordinal)
    {
        AccessToken
    };

    public static readonly IReadOnlySet<string> OpenIdConnect = new HashSet<string>(StringComparer.Ordinal)
    {
        IdToken,
        AccessToken
    };
}
