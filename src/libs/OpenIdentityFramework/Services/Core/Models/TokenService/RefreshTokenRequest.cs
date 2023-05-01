using System;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Core.Models.TokenService;

public class RefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public RefreshTokenRequest(
        TClient client,
        string? referenceAccessTokenHandle,
        string issuer,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        UserAuthentication? userAuthentication,
        DateTimeOffset issuedAt)
    {
        Client = client;
        ReferenceAccessTokenHandle = referenceAccessTokenHandle;
        Issuer = issuer;
        RequestedResources = requestedResources;
        UserAuthentication = userAuthentication;
        IssuedAt = issuedAt;
    }

    public TClient Client { get; }

    public string? ReferenceAccessTokenHandle { get; }

    public string Issuer { get; }

    public ValidResources<TScope, TResource, TResourceSecret> RequestedResources { get; }

    public UserAuthentication? UserAuthentication { get; }

    public DateTimeOffset IssuedAt { get; }
}
