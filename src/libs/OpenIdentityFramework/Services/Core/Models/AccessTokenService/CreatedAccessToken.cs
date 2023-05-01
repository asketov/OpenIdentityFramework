using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Core.Models.AccessTokenService;

public class CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public CreatedAccessToken(
        string accessTokenFormat,
        string issuer,
        TClient client,
        UserAuthentication? userAuthentication,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        IReadOnlySet<LightweightClaim> claims,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        long lifetimeInSeconds,
        string handle)
    {
        AccessTokenFormat = accessTokenFormat;
        Issuer = issuer;
        Client = client;
        UserAuthentication = userAuthentication;
        RequestedResources = requestedResources;
        Claims = claims;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        LifetimeInSeconds = lifetimeInSeconds;
        Handle = handle;
    }

    public string AccessTokenFormat { get; }
    public string Issuer { get; }
    public TClient Client { get; }
    public UserAuthentication? UserAuthentication { get; }
    public ValidResources<TScope, TResource, TResourceSecret> RequestedResources { get; }
    public IReadOnlySet<LightweightClaim> Claims { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public long LifetimeInSeconds { get; }
    public string Handle { get; }
}
