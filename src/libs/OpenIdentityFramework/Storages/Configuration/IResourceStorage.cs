using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Storages.Configuration.Models;

namespace OpenIdentityFramework.Storages.Configuration;

public interface IResourceStorage<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<ResourcesSearchResult<TScope, TResource, TResourceSecret>> FindScopesAndRelatedResourcesAsync(
        HttpContext httpContext,
        IReadOnlySet<string> scopesToSearch,
        CancellationToken cancellationToken);
}
