using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultTokenTypes
{
    public static readonly string IdToken = "id_token";
    public static readonly string AccessToken = "access_token";
    public static readonly string RefreshToken = "refresh_token";

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
