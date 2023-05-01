using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.TokenRequestValidator;

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
        string issuer,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        TAuthorizationCode? authorizationCode,
        TRefreshToken? refreshToken,
        string? authorizationCodeHandle,
        string? refreshTokenHandle)
    {
        GrantType = grantType;
        Client = client;
        Issuer = issuer;
        AllowedResources = allowedResources;
        AuthorizationCode = authorizationCode;
        RefreshToken = refreshToken;
        AuthorizationCodeHandle = authorizationCodeHandle;
        RefreshTokenHandle = refreshTokenHandle;
    }

    public string GrantType { get; }
    public TClient Client { get; }
    public string Issuer { get; }
    public ValidResources<TScope, TResource, TResourceSecret> AllowedResources { get; }
    public TAuthorizationCode? AuthorizationCode { get; }
    public TRefreshToken? RefreshToken { get; }
    public string? AuthorizationCodeHandle { get; }
    public string? RefreshTokenHandle { get; }
}
