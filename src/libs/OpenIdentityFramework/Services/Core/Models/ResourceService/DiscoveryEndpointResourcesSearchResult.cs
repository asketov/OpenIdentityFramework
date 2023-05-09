using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Services.Core.Models.ResourceService;

public class DiscoveryEndpointResourcesSearchResult
{
    public DiscoveryEndpointResourcesSearchResult(IReadOnlySet<string> scopes, IReadOnlySet<string> userClaimTypes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(userClaimTypes);
        Scopes = scopes;
        UserClaimTypes = userClaimTypes;
    }

    public IReadOnlySet<string> Scopes { get; }

    public IReadOnlySet<string> UserClaimTypes { get; }
}
