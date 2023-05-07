using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

public class ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
    where TRefreshToken : AbstractRefreshToken
{
    public ValidTokenRequest(
        string grantType,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        ResourceOwnerProfile? resourceOwnerProfile,
        ValidRefreshToken<TRefreshToken>? refreshToken,
        ValidAuthorizationCode<TAuthorizationCode>? authorizationCode,
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
    public ResourceOwnerProfile? ResourceOwnerProfile { get; }
    public ValidRefreshToken<TRefreshToken>? RefreshToken { get; }
    public ValidAuthorizationCode<TAuthorizationCode>? AuthorizationCode { get; }
    public string Issuer { get; }
}
