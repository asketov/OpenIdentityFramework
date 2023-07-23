using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Core;

public interface IResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<ResourceOwnerProfileResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> GetResourceOwnerProfileAsync(
        TRequestContext requestContext,
        TResourceOwnerEssentialClaims essentialClaims,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        CancellationToken cancellationToken);

    Task<bool> IsActiveAsync(
        TRequestContext requestContext,
        TResourceOwnerIdentifiers resourceOwnerIdentifiers,
        CancellationToken cancellationToken);
}
