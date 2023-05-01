using System;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Core.Models.AccessTokenService;

public class CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public CreateAccessTokenRequest(
        string grantType,
        TClient client,
        string issuer,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        UserAuthentication? userAuthentication,
        DateTimeOffset issuedAt)
    {
        GrantType = grantType;
        Client = client;
        Issuer = issuer;
        AllowedResources = allowedResources;
        UserAuthentication = userAuthentication;
        IssuedAt = issuedAt;
    }

    public string GrantType { get; }

    public TClient Client { get; }

    public string Issuer { get; }

    public ValidResources<TScope, TResource, TResourceSecret> AllowedResources { get; }

    public UserAuthentication? UserAuthentication { get; }

    public DateTimeOffset IssuedAt { get; }
}
