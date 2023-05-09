using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Core;

public interface IResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret>
    where TRequestContext : class, IRequestContext
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<ResourceOwnerProfileResult> GetResourceOwnerProfileAsync(
        TRequestContext requestContext,
        EssentialResourceOwnerClaims essentialClaims,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        CancellationToken cancellationToken);

    Task<bool> IsActiveAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        CancellationToken cancellationToken);
}
