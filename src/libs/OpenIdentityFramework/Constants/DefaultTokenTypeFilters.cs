using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultTokenTypeFilters
{
    public static readonly IReadOnlySet<string> AccessToken = new HashSet<string>(StringComparer.Ordinal)
    {
        DefaultTokenTypes.AccessToken
    };

    public static readonly IReadOnlySet<string> IdToken = new HashSet<string>(StringComparer.Ordinal)
    {
        DefaultTokenTypes.IdToken
    };

    public static readonly IReadOnlySet<string> IdTokenAccessToken = new HashSet<string>(StringComparer.Ordinal)
    {
        DefaultTokenTypes.IdToken,
        DefaultTokenTypes.AccessToken
    };
}
