using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Storages.Configuration.Models;

namespace OpenIdentityFramework.Storages.Configuration;

public interface IResourceStorage<TRequestContext, TScope, TResource, TResourceSecret>
    where TRequestContext : class, IRequestContext
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<ResourcesSearchResult<TScope, TResource, TResourceSecret>> FindScopesAndRelatedResourcesAsync(
        TRequestContext requestContext,
        IReadOnlySet<string> scopesToSearch,
        CancellationToken cancellationToken);

    Task<DiscoveryEndpointSearchResult> FindDiscoveryEndpointResourcesAsync(
        TRequestContext requestContext,
        IReadOnlySet<string> tokenTypesFilter,
        CancellationToken cancellationToken);
}
