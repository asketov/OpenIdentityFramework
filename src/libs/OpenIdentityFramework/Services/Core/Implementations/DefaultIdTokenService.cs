using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.IdTokenService;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;
using OpenIdentityFramework.Services.Cryptography;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultIdTokenService(
        IKeyMaterialService<TRequestContext> keyMaterialService,
        IIdTokenLeftMostHasher idTokenLeftMostHasher,
        IJwtService<TRequestContext> jwtService)
    {
        ArgumentNullException.ThrowIfNull(keyMaterialService);
        ArgumentNullException.ThrowIfNull(idTokenLeftMostHasher);
        ArgumentNullException.ThrowIfNull(jwtService);
        KeyMaterialService = keyMaterialService;
        IdTokenLeftMostHasher = idTokenLeftMostHasher;
        JwtService = jwtService;
    }

    protected IKeyMaterialService<TRequestContext> KeyMaterialService { get; }
    protected IIdTokenLeftMostHasher IdTokenLeftMostHasher { get; }
    protected IJwtService<TRequestContext> JwtService { get; }

    public virtual async Task<IdTokenCreationResult> CreateIdTokenAsync(
        TRequestContext requestContext,
        TClient client,
        string issuer,
        string? authorizationCodeHandle,
        string? accessTokenHandle,
        string? nonce,
        ResourceOwnerProfile resourceOwnerProfile,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(resourceOwnerProfile);
        ArgumentNullException.ThrowIfNull(grantedResources);
        cancellationToken.ThrowIfCancellationRequested();
        var keyMaterialSearchResult = await KeyMaterialService.FindSigningCredentialsAsync(requestContext, client.GetAllowedIdTokenSigningAlgorithms(), cancellationToken);
        if (keyMaterialSearchResult.HasError)
        {
            return new(keyMaterialSearchResult.ErrorDescription);
        }

        var roundIssuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAt.ToUnixTimeSeconds());
        var roundExpiresAt = DateTimeOffset.FromUnixTimeSeconds(roundIssuedAt.Add(client.GetIdTokenLifetime()).ToUnixTimeSeconds());
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
        var audiences = await GetIdTokenAudiencesAsync(requestContext, client.GetClientId(), cancellationToken);
        foreach (var audience in audiences)
        {
            result.Add(audience);
        }

        //authorizationCode
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // nonce - String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        // The value is passed through unmodified from the Authentication Request to the ID Token.
        // If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request.
        // If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request.
        // Authorization Servers SHOULD perform no other processing on nonce values used. The nonce value is a case sensitive string.
        if (!string.IsNullOrEmpty(nonce))
        {
            result.Add(new(DefaultJwtClaimTypes.Nonce, nonce));
        }

        // c_hash - Code hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the code value,
        // where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header.
        // For instance, if the alg is HS512, hash the code value with SHA-512, then take the left-most 256 bits and base64url encode them.
        // The c_hash value is a case sensitive string. If the ID Token is issued from the Authorization Endpoint with a code,
        // which is the case for the response_type values code id_token and code id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
        if (!string.IsNullOrEmpty(authorizationCodeHandle))
        {
            var authorizationCodeHash = IdTokenLeftMostHasher.ComputeHash(authorizationCodeHandle, keyMaterialSearchResult.SigningCredentials.Algorithm);
            result.Add(new(DefaultJwtClaimTypes.AccessTokenHash, authorizationCodeHash));
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11
        // at_hash - Access Token hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the access_token value,
        // where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header.
        // For instance, if the alg is RS256, hash the access_token value with SHA-256, then take the left-most 128 bits and base64url encode them. The at_hash value is a case sensitive string.
        // If the ID Token is issued from the Authorization Endpoint with an access_token value, which is the case for the response_type value code id_token token, this is REQUIRED;
        // otherwise, its inclusion is OPTIONAL.
        if (!string.IsNullOrEmpty(accessTokenHandle))
        {
            var accessTokenHash = IdTokenLeftMostHasher.ComputeHash(accessTokenHandle, keyMaterialSearchResult.SigningCredentials.Algorithm);
            result.Add(new(DefaultJwtClaimTypes.AccessTokenHash, accessTokenHash));
        }

        // exp - REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
        // The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value.
        // Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
        // Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
        result.Add(new(
            DefaultJwtClaimTypes.Expiration,
            roundExpiresAt.ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64));

        var issuedAtClaimValue = roundIssuedAt.ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture);
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

        foreach (var subjectClaim in GetSubjectClaims(resourceOwnerProfile.EssentialClaims))
        {
            result.Add(subjectClaim);
        }

        if (grantedResources.HasOpenId)
        {
            var profileClaimTypes = GetIdTokenProfileClaimTypes(grantedResources);
            foreach (var profileClaim in resourceOwnerProfile.ProfileClaims)
            {
                if (profileClaimTypes.Contains(profileClaim.Type))
                {
                    result.Add(profileClaim);
                }
            }
        }

        foreach (var scopeClaim in GetScopeClaims(grantedResources))
        {
            result.Add(scopeClaim);
        }

        var idTokenHandle = await JwtService.CreateIdTokenAsync(
            requestContext,
            keyMaterialSearchResult.SigningCredentials,
            result,
            cancellationToken);
        var createdToken = new CreatedIdToken(idTokenHandle);
        return new(createdToken);
    }

    protected virtual Task<IReadOnlySet<LightweightClaim>> GetIdTokenAudiencesAsync(
        TRequestContext requestContext,
        string clientId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlySet<LightweightClaim> audiences = new HashSet<LightweightClaim>(LightweightClaim.EqualityComparer)
        {
            new(DefaultJwtClaimTypes.Audience, clientId)
        };
        return Task.FromResult(audiences);
    }

    protected virtual IEnumerable<LightweightClaim> GetSubjectClaims(EssentialResourceOwnerClaims essentialClaims)
    {
        ArgumentNullException.ThrowIfNull(essentialClaims);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // sub - REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
        // It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
        yield return new(DefaultJwtClaimTypes.Subject, essentialClaims.Identifiers.SubjectId);

        // https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.2.1
        // The sid (session ID) Claim used in ID Tokens and as a Logout Token parameter has the following definition
        // sid - OPTIONAL. Session ID - String identifier for a Session. This represents a Session of a User Agent or device for a logged-in End-User at an RP.
        // Different sid values are used to identify distinct sessions at an OP. The sid value need only be unique in the context of a particular issuer.
        // Its contents are opaque to the RP. Its syntax is the same as an OAuth 2.0 Client Identifier.
        yield return new(DefaultJwtClaimTypes.SessionId, essentialClaims.Identifiers.SessionId);

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // auth_time - Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
        // When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL.
        yield return new(
            DefaultJwtClaimTypes.AuthenticationTime,
            essentialClaims.AuthenticatedAt.ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64);
    }

    protected virtual IReadOnlySet<string> GetIdTokenProfileClaimTypes(ValidResources<TScope, TResource, TResourceSecret> grantedResources)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        var result = new HashSet<string>(256, StringComparer.Ordinal);
        foreach (var idTokenScope in grantedResources.IdTokenScopes)
        {
            foreach (var userClaimType in idTokenScope.GetUserClaimTypes())
            {
                if (!DefaultJwtClaimTypes.Restrictions.Contains(userClaimType))
                {
                    result.Add(userClaimType);
                }
            }
        }

        return result;
    }

    protected virtual IEnumerable<LightweightClaim> GetScopeClaims(ValidResources<TScope, TResource, TResourceSecret> grantedResources)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        foreach (var scope in grantedResources.RawScopes)
        {
            yield return new(DefaultJwtClaimTypes.Scope, scope);
        }
    }
}
