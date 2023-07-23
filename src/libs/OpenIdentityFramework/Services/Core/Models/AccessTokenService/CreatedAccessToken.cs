using System;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Core.Models.AccessTokenService;

public class CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers

{
    public CreatedAccessToken(
        string accessTokenFormat,
        string handle,
        TClient client,
        ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? resourceOwnerProfile,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        DateTimeOffset actualIssuedAt,
        DateTimeOffset actualExpiresAt)
    {
        AccessTokenFormat = accessTokenFormat;
        Handle = handle;
        Client = client;
        ResourceOwnerProfile = resourceOwnerProfile;
        GrantedResources = grantedResources;
        ActualIssuedAt = actualIssuedAt;
        var lifetimeInSeconds = actualExpiresAt.Subtract(actualIssuedAt).Ticks / TimeSpan.TicksPerSecond;
        if (lifetimeInSeconds < 0)
        {
            lifetimeInSeconds = 0;
        }

        LifetimeInSeconds = lifetimeInSeconds;
    }

    public string AccessTokenFormat { get; }
    public string Handle { get; }
    public TClient Client { get; }
    public ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? ResourceOwnerProfile { get; }
    public ValidResources<TScope, TResource, TResourceSecret> GrantedResources { get; }
    public DateTimeOffset ActualIssuedAt { get; }
    public long LifetimeInSeconds { get; }
}
