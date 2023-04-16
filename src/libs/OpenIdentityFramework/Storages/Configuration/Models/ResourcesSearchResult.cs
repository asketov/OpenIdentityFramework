using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Storages.Configuration.Models;

public class ResourcesSearchResult<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public ResourcesSearchResult(IReadOnlySet<TScope> scopes, IReadOnlySet<TResource> resources)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(resources);
        Scopes = scopes;
        Resources = resources;
    }

    public IReadOnlySet<TScope> Scopes { get; }
    public IReadOnlySet<TResource> Resources { get; }
}
