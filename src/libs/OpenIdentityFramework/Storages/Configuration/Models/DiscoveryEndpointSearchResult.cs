using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Storages.Configuration.Models;

public class DiscoveryEndpointSearchResult
{
    public DiscoveryEndpointSearchResult(IReadOnlySet<string> scopes, IReadOnlySet<string> userClaimTypes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(userClaimTypes);
        Scopes = scopes;
        UserClaimTypes = userClaimTypes;
    }

    public IReadOnlySet<string> Scopes { get; }

    public IReadOnlySet<string> UserClaimTypes { get; }
}
