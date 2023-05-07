using System;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;

namespace OpenIdentityFramework.Services.Core.Models.IdTokenService;

public class CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public CreateIdTokenRequest(
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        string? nonce,
        string issuer,
        DateTimeOffset issuedAt,
        string? accessToken,
        string? authorizationCode,
        bool forceIncludeUserClaimsInIdToken)
    {
        Client = client;
        AllowedResources = allowedResources;
        Nonce = nonce;
        Issuer = issuer;
        IssuedAt = issuedAt;
        AccessToken = accessToken;
        AuthorizationCode = authorizationCode;
        ForceIncludeUserClaimsInIdToken = forceIncludeUserClaimsInIdToken;
    }

    public TClient Client { get; }

    public ValidResources<TScope, TResource, TResourceSecret> AllowedResources { get; }

    public string? Nonce { get; }

    public string Issuer { get; }

    public DateTimeOffset IssuedAt { get; }

    public string? AccessToken { get; }

    public string? AuthorizationCode { get; }

    public bool ForceIncludeUserClaimsInIdToken { get; }
}
