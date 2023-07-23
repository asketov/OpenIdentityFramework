using System;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode;

public class ValidAuthorizationCodeTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public ValidAuthorizationCodeTokenRequest(
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        string authorizationCodeHandle,
        TAuthorizationCode authorizationCode,
        ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> resourceOwnerProfile)
    {
        Client = client;
        AllowedResources = allowedResources;
        AuthorizationCodeHandle = authorizationCodeHandle;
        AuthorizationCode = authorizationCode;
        ResourceOwnerProfile = resourceOwnerProfile;
    }

    public TClient Client { get; }
    public ValidResources<TScope, TResource, TResourceSecret> AllowedResources { get; }
    public string AuthorizationCodeHandle { get; }
    public TAuthorizationCode AuthorizationCode { get; }
    public ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> ResourceOwnerProfile { get; }
}
