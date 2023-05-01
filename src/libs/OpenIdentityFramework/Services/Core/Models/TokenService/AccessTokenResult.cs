using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Core.Models.TokenService;

public class AccessTokenResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public AccessTokenResult(
        string accessTokenType,
        string issuer,
        string grantType,
        TClient client,
        UserAuthentication? userAuthentication,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        IReadOnlySet<LightweightClaim> claims,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        long lifetimeInSeconds,
        string handle)
    {
        AccessTokenType = accessTokenType;
        Issuer = issuer;
        GrantType = grantType;
        Client = client;
        UserAuthentication = userAuthentication;
        RequestedResources = requestedResources;
        Claims = claims;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        LifetimeInSeconds = lifetimeInSeconds;
        Handle = handle;
    }

    public string AccessTokenType { get; }
    public string Issuer { get; }
    public string GrantType { get; }
    public TClient Client { get; }
    public UserAuthentication? UserAuthentication { get; }
    public ValidResources<TScope, TResource, TResourceSecret> RequestedResources { get; }
    public IReadOnlySet<LightweightClaim> Claims { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public long LifetimeInSeconds { get; }
    public string Handle { get; }
}
