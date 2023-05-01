using System;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Core.Models.TokenService;

public class AccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public AccessTokenRequest(
        string grantType,
        TClient client,
        string issuer,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        UserAuthentication? userAuthentication,
        DateTimeOffset issuedAt)
    {
        GrantType = grantType;
        Client = client;
        Issuer = issuer;
        RequestedResources = requestedResources;
        UserAuthentication = userAuthentication;
        IssuedAt = issuedAt;
    }

    public string GrantType { get; }

    public TClient Client { get; }

    public string Issuer { get; }

    public ValidResources<TScope, TResource, TResourceSecret> RequestedResources { get; }

    public UserAuthentication? UserAuthentication { get; }

    public DateTimeOffset IssuedAt { get; }
}
