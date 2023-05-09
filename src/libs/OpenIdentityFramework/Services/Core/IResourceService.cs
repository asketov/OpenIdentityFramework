using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Core;

public interface IResourceService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<ResourcesValidationResult<TScope, TResource, TResourceSecret>> ValidateRequestedScopesAsync(
        TRequestContext requestContext,
        TClient client,
        IReadOnlySet<string> requestedScopes,
        IReadOnlySet<string> tokenTypesFilter,
        CancellationToken cancellationToken);

    Task<DiscoveryEndpointResourcesSearchResult> FindDiscoveryEndpointResourcesAsync(
        TRequestContext requestContext,
        IReadOnlySet<string> tokenTypesFilter,
        CancellationToken cancellationToken);
}
