using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.IdTokenService;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Core;

public interface IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<IdTokenCreationResult> CreateIdTokenAsync(
        TRequestContext requestContext,
        TClient client,
        string issuer,
        string? authorizationCodeHandle,
        string? accessTokenHandle,
        string? nonce,
        ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> resourceOwnerProfile,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken);
}
