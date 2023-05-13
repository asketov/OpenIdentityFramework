using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

public class ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public ValidTokenRequest(
        string grantType,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? resourceOwnerProfile,
        ValidRefreshToken<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? refreshToken,
        ValidAuthorizationCode<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? authorizationCode,
        string issuer)
    {
        GrantType = grantType;
        Client = client;
        AllowedResources = allowedResources;
        ResourceOwnerProfile = resourceOwnerProfile;
        RefreshToken = refreshToken;
        AuthorizationCode = authorizationCode;
        Issuer = issuer;
    }

    public string GrantType { get; }
    public TClient Client { get; }
    public ValidResources<TScope, TResource, TResourceSecret> AllowedResources { get; }
    public ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? ResourceOwnerProfile { get; }
    public ValidRefreshToken<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? RefreshToken { get; }
    public ValidAuthorizationCode<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? AuthorizationCode { get; }
    public string Issuer { get; }
}
