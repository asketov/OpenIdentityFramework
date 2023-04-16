using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.ResourceValidator;

public class ValidResources<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public ValidResources(IReadOnlyCollection<TScope> scopes, IReadOnlyCollection<TResource> resources, bool hasOfflineAccess)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(resources);
        Scopes = scopes;
        Resources = resources;
        HasOfflineAccess = hasOfflineAccess;
    }

    public IReadOnlyCollection<TScope> Scopes { get; }
    public IReadOnlyCollection<TResource> Resources { get; }

    public bool HasOfflineAccess { get; }
}
