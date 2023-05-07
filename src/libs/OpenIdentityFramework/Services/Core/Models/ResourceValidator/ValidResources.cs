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
    public ValidResources(IReadOnlySet<TScope> allScopes, IReadOnlySet<TResource> resources, bool hasOfflineAccess)
    {
        ArgumentNullException.ThrowIfNull(allScopes);
        ArgumentNullException.ThrowIfNull(resources);
        Resources = resources;
        HasOfflineAccess = hasOfflineAccess;
        var scopesCapacity = allScopes.Count + 1;
        var rawScopes = new HashSet<string>(scopesCapacity, StringComparer.Ordinal);
        var requiredScopes = new HashSet<string>(scopesCapacity, StringComparer.Ordinal);
        var idTokenScopes = new HashSet<TScope>();
        var accessTokenScopes = new HashSet<TScope>();
        foreach (var scope in allScopes)
        {
            var scopeName = scope.GetProtocolName();
            var scopeTokenType = scope.GetScopeTokenType();
            rawScopes.Add(scopeName);
            if (scope.IsRequired())
            {
                requiredScopes.Add(scopeName);
            }

            if (scopeTokenType == DefaultTokenTypes.IdToken)
            {
                idTokenScopes.Add(scope);
            }
            else if (scopeTokenType == DefaultTokenTypes.AccessToken)
            {
                accessTokenScopes.Add(scope);
            }

            if (scopeName == DefaultScopes.OpenId)
            {
                HasOpenId = true;
            }
        }

        if (hasOfflineAccess)
        {
            rawScopes.Add(DefaultScopes.OfflineAccess);
        }

        RawScopes = rawScopes;
        RequiredScopes = requiredScopes;
        IdTokenScopes = idTokenScopes;
        AccessTokenScopes = accessTokenScopes;
    }

    public IReadOnlySet<TScope> IdTokenScopes { get; }
    public IReadOnlySet<TScope> AccessTokenScopes { get; }
    public IReadOnlySet<string> RawScopes { get; }
    public IReadOnlySet<string> RequiredScopes { get; }
    public IReadOnlySet<TResource> Resources { get; }
    public bool HasOfflineAccess { get; }
    public bool HasOpenId { get; }

    public bool HasAnyScope()
    {
        return RawScopes.Count > 0;
    }

    public bool IsFullyCoveredBy(IReadOnlySet<string> providedScopes)
    {
        ArgumentNullException.ThrowIfNull(providedScopes);
        return providedScopes.IsSupersetOf(RawScopes);
    }

    public bool IsRequiredScopesCoveredBy(IReadOnlySet<string> providedScopes)
    {
        ArgumentNullException.ThrowIfNull(providedScopes);
        return providedScopes.IsSupersetOf(RequiredScopes);
    }

    public ValidResources<TScope, TResource, TResourceSecret> FilterGrantedScopes(IReadOnlySet<string> grantedScopes)
    {
        ArgumentNullException.ThrowIfNull(grantedScopes);
        var scopesCapacity = IdTokenScopes.Count + AccessTokenScopes.Count;
        var scopes = new HashSet<TScope>(scopesCapacity);
        var scopesNames = new HashSet<string>(scopesCapacity);
        var resources = new HashSet<TResource>(Resources.Count);
        foreach (var scope in IdTokenScopes)
        {
            var protocolName = scope.GetProtocolName();
            if (grantedScopes.Contains(protocolName))
            {
                scopes.Add(scope);
                scopesNames.Add(protocolName);
            }
        }

        foreach (var scope in AccessTokenScopes)
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
