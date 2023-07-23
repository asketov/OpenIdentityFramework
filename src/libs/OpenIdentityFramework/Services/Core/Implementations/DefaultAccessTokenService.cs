using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;
using OpenIdentityFramework.Services.Static.Cryptography;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    : IAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TAccessToken : AbstractAccessToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultAccessTokenService(
        OpenIdentityFrameworkOptions frameworkOptions,
        TimeProvider timeProvider,
        IKeyMaterialService<TRequestContext> keyMaterial,
        IJwtService<TRequestContext> jwtService,
        IAccessTokenStorage<TRequestContext, TAccessToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> accessTokenStorage)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentNullException.ThrowIfNull(jwtService);
        ArgumentNullException.ThrowIfNull(accessTokenStorage);
        FrameworkOptions = frameworkOptions;
        TimeProvider = timeProvider;
        KeyMaterial = keyMaterial;
        JwtService = jwtService;
        AccessTokenStorage = accessTokenStorage;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected TimeProvider TimeProvider { get; }
    protected IKeyMaterialService<TRequestContext> KeyMaterial { get; }
    protected IJwtService<TRequestContext> JwtService { get; }
    protected IAccessTokenStorage<TRequestContext, TAccessToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> AccessTokenStorage { get; }

    public virtual async Task<AccessTokenCreationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> CreateAccessTokenAsync(
        TRequestContext requestContext,
        TClient client,
        string issuer,
        string grantType,
        ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? resourceOwnerProfile,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(grantedResources);
        cancellationToken.ThrowIfCancellationRequested();
        var accessTokenStrategy = client.GetAccessTokenStrategy();
        if (accessTokenStrategy != DefaultAccessTokenStrategy.Jwt && accessTokenStrategy != DefaultAccessTokenStrategy.Opaque)
        {
            return new("Unsupported access token format");
        }

        var roundIssuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAt.ToUnixTimeSeconds());
        var roundExpiresAt = DateTimeOffset.FromUnixTimeSeconds(roundIssuedAt.Add(TimeSpan.FromSeconds(client.GetAccessTokenLifetime())).ToUnixTimeSeconds());
        var accessTokenClaims = await GetAccessTokenClaimsAsync(
            requestContext,
            client,
            issuer,
            grantType,
            resourceOwnerProfile,
            grantedResources,
            roundIssuedAt,
            roundExpiresAt,
            cancellationToken);
        string accessTokenHandle;
        if (accessTokenStrategy == DefaultAccessTokenStrategy.Jwt)
        {
            HashSet<string>? accessTokenSignedResponseAlgorithms = null;
            string? accessTokenSignedResponseAlg;
            if (!string.IsNullOrEmpty(accessTokenSignedResponseAlg = client.GetAccessTokenSignedResponseAlg()))
            {
                accessTokenSignedResponseAlgorithms = new(StringComparer.Ordinal)
                {
                    accessTokenSignedResponseAlg
                };
            }

            var keyMaterialSearchResult = await KeyMaterial.FindSigningCredentialsAsync(requestContext, accessTokenSignedResponseAlgorithms, cancellationToken);
            if (keyMaterialSearchResult.HasError)
            {
                return new(keyMaterialSearchResult.ErrorDescription);
            }

            accessTokenHandle = await JwtService.CreateAccessTokenAsync(
                requestContext,
                keyMaterialSearchResult.SigningCredentials,
                accessTokenClaims,
                cancellationToken);
        }
        else if (accessTokenStrategy == DefaultAccessTokenStrategy.Opaque)
        {
            accessTokenHandle = await AccessTokenStorage.CreateAsync(
                requestContext,
                client.GetClientId(),
                resourceOwnerProfile?.EssentialClaims,
                grantedResources.RawScopes,
                accessTokenClaims,
                roundIssuedAt,
                roundExpiresAt,
                cancellationToken);
        }
        else
        {
            return new("Unsupported access token format");
        }

        var createdAccessToken = new CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>(
            accessTokenStrategy,
            accessTokenHandle,
            client,
            resourceOwnerProfile,
            grantedResources,
            roundIssuedAt,
            roundExpiresAt);
        return new(createdAccessToken);
    }

    public virtual async Task<TAccessToken?> FindAsync(
        TRequestContext requestContext,
        string clientId,
        string accessTokenHandle,
        CancellationToken cancellationToken)
    {
        var accessToken = await AccessTokenStorage.FindAsync(requestContext, accessTokenHandle, cancellationToken);
        if (accessToken == null)
        {
            return null;
        }

        if (accessToken.GetClientId() == clientId)
        {
            var expiresAt = accessToken.GetExpirationDate();
            if (TimeProvider.GetUtcNow() > expiresAt)
            {
                await AccessTokenStorage.DeleteAsync(requestContext, accessTokenHandle, cancellationToken);
                return null;
            }

            return accessToken;
        }

        return null;
    }


    public virtual async Task DeleteAsync(
        TRequestContext requestContext,
        string accessTokenHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await AccessTokenStorage.DeleteAsync(requestContext, accessTokenHandle, cancellationToken);
    }

    protected virtual async Task<IReadOnlySet<LightweightClaim>> GetAccessTokenClaimsAsync(
        TRequestContext requestContext,
        TClient client,
        string issuer,
        string grantType,
        ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? resourceOwnerProfile,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        var result = new HashSet<LightweightClaim>(256, LightweightClaim.EqualityComparer)
        {
            // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
            // iss - REQUIRED. Issuer Identifier for the Issuer of the response.
            // The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
            new(DefaultJwtClaimTypes.Issuer, issuer)
        };
        // aud - REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value.
        // It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings.
        // In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
        var audiences = await GetAccessTokenAudiencesAsync(requestContext, client.GetClientId(), grantedResources, issuer, cancellationToken);
        foreach (var audience in audiences)
        {
            result.Add(audience);
        }

        // exp - REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
        // The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value.
        // Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
        // Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
        result.Add(new(
            DefaultJwtClaimTypes.Expiration,
            expiresAt.ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64));

        var issuedAtClaimValue = issuedAt.ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture);
        // iat - REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
        result.Add(new(
            DefaultJwtClaimTypes.IssuedAt,
            issuedAtClaimValue,
            ClaimValueTypes.Integer64));

        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
        // "nbf" (Not Before) Claim - The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
        result.Add(new(
            DefaultJwtClaimTypes.NotBefore,
            issuedAtClaimValue,
            ClaimValueTypes.Integer64));

        if (client.ShouldIncludeJwtIdIntoAccessToken() && client.GetAccessTokenStrategy() == DefaultAccessTokenStrategy.Jwt)
        {
            var jwtId = CryptoRandom.Create(16);
            result.Add(new(DefaultJwtClaimTypes.JwtId, jwtId));
        }

        if (resourceOwnerProfile is not null)
        {
            foreach (var essentialClaim in GetEssentialClaims(resourceOwnerProfile.EssentialClaims))
            {
                result.Add(essentialClaim);
            }

            var profileClaimTypes = GetAccessTokenProfileClaimTypes(grantedResources);
            foreach (var profileClaim in resourceOwnerProfile.ProfileClaims)
            {
                if (profileClaimTypes.Contains(profileClaim.Type))
                {
                    result.Add(profileClaim);
                }
            }
        }

        foreach (var scopeClaim in GetScopeClaims(grantedResources, grantType))
        {
            result.Add(scopeClaim);
        }

        return result;
    }

    protected virtual Task<IReadOnlySet<LightweightClaim>> GetAccessTokenAudiencesAsync(
        TRequestContext requestContext,
        string clientId,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        cancellationToken.ThrowIfCancellationRequested();
        var audiences = new HashSet<LightweightClaim>(grantedResources.Resources.Count + 1, LightweightClaim.EqualityComparer)
        {
            new(DefaultJwtClaimTypes.Audience, clientId)
        };
        foreach (var resource in grantedResources.Resources)
        {
            audiences.Add(new(DefaultJwtClaimTypes.Audience, resource.GetResourceId()));
        }

        if (FrameworkOptions.EmitStaticAudienceClaim)
        {
            var issuerAudience = new Uri(new(issuer, UriKind.Absolute), new Uri("resources", UriKind.Relative)).ToString();
            audiences.Add(new(DefaultJwtClaimTypes.Audience, issuerAudience));
        }

        IReadOnlySet<LightweightClaim> result = audiences;
        return Task.FromResult(result);
    }

    protected virtual IEnumerable<LightweightClaim> GetEssentialClaims(TResourceOwnerEssentialClaims essentialClaims)
    {
        ArgumentNullException.ThrowIfNull(essentialClaims);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // sub - REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
        // It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
        yield return new(DefaultJwtClaimTypes.Subject, essentialClaims.GetResourceOwnerIdentifiers().GetSubjectId());

        // https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.2.1
        // The sid (session ID) Claim used in ID Tokens and as a Logout Token parameter has the following definition
        // sid - OPTIONAL. Session ID - String identifier for a Session. This represents a Session of a User Agent or device for a logged-in End-User at an RP.
        // Different sid values are used to identify distinct sessions at an OP. The sid value need only be unique in the context of a particular issuer.
        // Its contents are opaque to the RP. Its syntax is the same as an OAuth 2.0 Client Identifier.
        yield return new(DefaultJwtClaimTypes.SessionId, essentialClaims.GetResourceOwnerIdentifiers().GetSessionId());

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // auth_time - Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
        // When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL.
        yield return new(
            DefaultJwtClaimTypes.AuthenticationTime,
            essentialClaims.GetAuthenticationDate().ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64);
    }

    protected virtual IReadOnlySet<string> GetAccessTokenProfileClaimTypes(ValidResources<TScope, TResource, TResourceSecret> grantedResources)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        var result = new HashSet<string>(256, StringComparer.Ordinal);
        foreach (var accessTokenScope in grantedResources.AccessTokenScopes)
        {
            foreach (var userClaimType in accessTokenScope.GetUserClaimTypes())
            {
                if (!DefaultJwtClaimTypes.Restrictions.Contains(userClaimType))
                {
                    result.Add(userClaimType);
                }
            }
        }

        return result;
    }

    protected virtual IEnumerable<LightweightClaim> GetScopeClaims(
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        string grantType)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);

        if (grantType == DefaultGrantTypes.ClientCredentials && grantedResources.HasOfflineAccess)
        {
            foreach (var scope in grantedResources.RawScopes)
            {
                if (scope != DefaultScopes.OfflineAccess)
                {
                    yield return new(DefaultJwtClaimTypes.Scope, scope);
                }
            }
        }
        else
        {
            foreach (var scope in grantedResources.RawScopes)
            {
                yield return new(DefaultJwtClaimTypes.Scope, scope);
            }
        }
    }
}
