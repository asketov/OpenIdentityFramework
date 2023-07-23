using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestConsent, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TAuthorizeRequestConsent : AbstractAuthorizeRequestConsent<TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers

{
    Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> ProcessInteractionRequirementsAsync(
        TRequestContext requestContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        ResourceOwnerAuthentication<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? resourceOwnerAuthentication,
        TAuthorizeRequestConsent? authorizeRequestConsent,
        CancellationToken cancellationToken);
}
