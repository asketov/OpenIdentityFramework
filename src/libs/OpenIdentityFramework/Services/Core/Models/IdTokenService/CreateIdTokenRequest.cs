using System;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Core.Models.IdTokenService;

public class CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public CreateIdTokenRequest(
        UserAuthentication userAuthentication,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        string? nonce,
        string? state,
        string issuer,
        DateTimeOffset issuedAt,
        string? accessToken,
        string? authorizationCode,
        bool forceIncludeUserClaimsInIdToken)
    {
        UserAuthentication = userAuthentication;
        Client = client;
        AllowedResources = allowedResources;
        Nonce = nonce;
        State = state;
        Issuer = issuer;
        IssuedAt = issuedAt;
        AccessToken = accessToken;
        AuthorizationCode = authorizationCode;
        ForceIncludeUserClaimsInIdToken = forceIncludeUserClaimsInIdToken;
    }

    public UserAuthentication UserAuthentication { get; }

    public TClient Client { get; }

    public ValidResources<TScope, TResource, TResourceSecret> AllowedResources { get; }

    public string? Nonce { get; }

    public string? State { get; }

    public string Issuer { get; }

    public DateTimeOffset IssuedAt { get; }

    public string? AccessToken { get; }

    public string? AuthorizationCode { get; }

    public bool ForceIncludeUserClaimsInIdToken { get; }
}
