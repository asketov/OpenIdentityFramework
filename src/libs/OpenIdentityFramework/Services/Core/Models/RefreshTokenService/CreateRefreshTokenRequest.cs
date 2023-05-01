using System;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;

namespace OpenIdentityFramework.Services.Core.Models.RefreshTokenService;

public class CreateRefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRefreshToken : AbstractRefreshToken
{
    public CreateRefreshTokenRequest(
        TClient client,
        CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret> accessToken,
        TRefreshToken? previousRefreshToken,
        string issuer,
        DateTimeOffset issuedAt)
    {
        Client = client;
        AccessToken = accessToken;
        PreviousRefreshToken = previousRefreshToken;
        Issuer = issuer;
        IssuedAt = issuedAt;
    }

    public TClient Client { get; }
    public CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret> AccessToken { get; }

    public TRefreshToken? PreviousRefreshToken { get; }
    public string Issuer { get; }

    public DateTimeOffset IssuedAt { get; }
}
