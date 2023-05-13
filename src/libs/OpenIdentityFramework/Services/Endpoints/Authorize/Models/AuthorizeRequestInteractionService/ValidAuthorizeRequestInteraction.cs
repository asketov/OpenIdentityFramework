using System;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;

public class ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public ValidAuthorizeRequestInteraction(
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        ResourceOwnerAuthentication<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> resourceOwnerAuthentication,
        ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> resourceOwnerProfile)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(grantedResources);
        ArgumentNullException.ThrowIfNull(resourceOwnerAuthentication);
        ArgumentNullException.ThrowIfNull(resourceOwnerProfile);
        AuthorizeRequest = authorizeRequest;
        GrantedResources = grantedResources;
        ResourceOwnerAuthentication = resourceOwnerAuthentication;
        ResourceOwnerProfile = resourceOwnerProfile;
    }

    public ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> AuthorizeRequest { get; }
    public ValidResources<TScope, TResource, TResourceSecret> GrantedResources { get; }
    public ResourceOwnerAuthentication<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> ResourceOwnerAuthentication { get; }
    public ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> ResourceOwnerProfile { get; }
}
