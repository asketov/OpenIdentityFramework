using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Configuration;
using OpenIdentityFramework.Storages.Configuration;
using OpenIdentityFramework.Storages.Configuration.Models;

namespace OpenIdentityFramework.InMemory.Storages.Configuration;

public class InMemoryResourceStorage : IResourceStorage<InMemoryRequestContext, InMemoryScope, InMemoryResource, InMemoryResourceSecret>
{
    private readonly List<InMemoryResource> _resources;
    private readonly List<InMemoryScope> _scopes;

    public InMemoryResourceStorage(IEnumerable<InMemoryScope> scopes, IEnumerable<InMemoryResource> resources)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(resources);
        _scopes = scopes.ToList();
        _resources = resources.ToList();
    }

    public Task<ResourcesSearchResult<InMemoryScope, InMemoryResource, InMemoryResourceSecret>> FindScopesAndRelatedResourcesAsync(
        InMemoryRequestContext requestContext,
        IReadOnlySet<string> scopesToSearch,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var scopes = _scopes.Where(x => scopesToSearch.Contains(x.ProtocolName)).ToHashSet();
        var accessTokenScopes = scopes
            .Where(x => x.ScopeTokenType == DefaultTokenTypes.AccessToken)
            .Select(x => x.ProtocolName)
            .ToHashSet(StringComparer.Ordinal);
        var resources = _resources.Where(x => x.AccessTokenScopes.Overlaps(accessTokenScopes)).ToHashSet();
        var result = new ResourcesSearchResult<InMemoryScope, InMemoryResource, InMemoryResourceSecret>(scopes, resources);
        return Task.FromResult(result);
    }

    public Task<DiscoveryEndpointSearchResult> FindDiscoveryEndpointResourcesAsync(
        InMemoryRequestContext requestContext,
        IReadOnlySet<string> tokenTypesFilter,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var scopes = _scopes.Where(x => x.ShowInDiscovery).Select(x => new
        {
            x.ProtocolName,
            x.UserClaimTypes
        }).ToList();
        var discoveryScopes = scopes.Select(x => x.ProtocolName).ToHashSet(StringComparer.Ordinal);
        var discoveryUserClaimTypes = scopes.SelectMany(x => x.UserClaimTypes).ToHashSet(StringComparer.Ordinal);
        var result = new DiscoveryEndpointSearchResult(discoveryScopes, discoveryUserClaimTypes);
        return Task.FromResult(result);
    }
}
