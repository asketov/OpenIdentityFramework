using System;
using System.Collections.Generic;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.ResourceValidator;

public class ValidResources<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    private readonly IReadOnlySet<string> _requiredScopes;

    public ValidResources(IReadOnlySet<TScope> scopes, IReadOnlySet<TResource> resources, bool hasOfflineAccess)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(resources);
        Scopes = scopes;
        Resources = resources;
        HasOfflineAccess = hasOfflineAccess;
        var rawScopes = new HashSet<string>(scopes.Count + 1, StringComparer.Ordinal);
        var requiredScopes = new HashSet<string>(scopes.Count + 1, StringComparer.Ordinal);
        foreach (var scope in scopes)
        {
            var scopeName = scope.GetProtocolName();
            rawScopes.Add(scopeName);
            if (scope.IsRequired())
            {
                requiredScopes.Add(scopeName);
            }
        }

        if (hasOfflineAccess)
        {
            rawScopes.Add(DefaultScopes.OfflineAccess);
        }

        Raw = rawScopes;
        _requiredScopes = requiredScopes;
    }

    public IReadOnlySet<TScope> Scopes { get; }
    public IReadOnlySet<TResource> Resources { get; }
    public bool HasOfflineAccess { get; }
    public IReadOnlySet<string> Raw { get; }

    public bool HasAnyScope()
    {
        return Raw.Count > 0;
    }

    public bool IsFullyCoveredBy(IReadOnlySet<string> providedScopes)
    {
        ArgumentNullException.ThrowIfNull(providedScopes);
        return providedScopes.IsSupersetOf(Raw);
    }

    public bool IsRequiredScopesCoveredBy(IReadOnlySet<string> providedScopes)
    {
        ArgumentNullException.ThrowIfNull(providedScopes);
        return providedScopes.IsSupersetOf(_requiredScopes);
    }

    public ValidResources<TScope, TResource, TResourceSecret> FilterGrantedScopes(IReadOnlySet<string> grantedScopes)
    {
        ArgumentNullException.ThrowIfNull(grantedScopes);
        var scopes = new HashSet<TScope>(Scopes.Count);
        var scopesNames = new HashSet<string>(Scopes.Count);
        var resources = new HashSet<TResource>(Resources.Count);
        foreach (var scope in Scopes)
        {
            var protocolName = scope.GetProtocolName();
            if (grantedScopes.Contains(protocolName))
            {
                scopes.Add(scope);
                scopesNames.Add(protocolName);
            }
        }

        foreach (var resource in Resources)
        {
            foreach (var resourceScope in resource.GetAccessTokenScopes())
            {
                if (scopesNames.Contains(resourceScope))
                {
                    resources.Add(resource);
                    break;
                }
            }
        }

        return new(scopes, resources, HasOfflineAccess);
    }
}
