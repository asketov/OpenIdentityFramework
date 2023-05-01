using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;
using OpenIdentityFramework.Services.Core.Models.IdTokenService;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;
using OpenIdentityFramework.Services.Cryptography;
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Services.Static.Cryptography;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultTokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultTokenClaimsService(
        OpenIdentityFrameworkOptions frameworkOptions,
        IUserProfileService userProfile,
        IIdTokenLeftMostHasher idTokenLeftMostHasher)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(userProfile);
        ArgumentNullException.ThrowIfNull(idTokenLeftMostHasher);
        FrameworkOptions = frameworkOptions;
        UserProfile = userProfile;
        IdTokenLeftMostHasher = idTokenLeftMostHasher;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IUserProfileService UserProfile { get; }
    protected IIdTokenLeftMostHasher IdTokenLeftMostHasher { get; }

    public virtual async Task<HashSet<LightweightClaim>> GetIdentityTokenClaimsAsync(
        HttpContext httpContext,
        CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createIdTokenRequest,
        SigningCredentials signingCredentials,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createIdTokenRequest);
        ArgumentNullException.ThrowIfNull(signingCredentials);
        cancellationToken.ThrowIfCancellationRequested();
        var result = new HashSet<LightweightClaim>(256, LightweightClaim.EqualityComparer)
        {
            // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
            // iss - REQUIRED. Issuer Identifier for the Issuer of the response.
            // The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
            new(DefaultJwtClaimTypes.Issuer, createIdTokenRequest.Issuer)
        };
        // aud - REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value.
        // It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings.
        // In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
        var audiences = await GetIdTokenAudiencesAsync(httpContext, createIdTokenRequest, cancellationToken);
        foreach (var audience in audiences)
        {
            result.Add(audience);
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // nonce - String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        // The value is passed through unmodified from the Authentication Request to the ID Token.
        // If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request.
        // If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request.
        // Authorization Servers SHOULD perform no other processing on nonce values used. The nonce value is a case sensitive string.
        if (createIdTokenRequest.Nonce != null)
        {
            result.Add(new(DefaultJwtClaimTypes.Nonce, createIdTokenRequest.Nonce));
        }

        if (!string.IsNullOrEmpty(createIdTokenRequest.AccessToken))
        {
            // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11
            // at_hash - Access Token hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the access_token value,
            // where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header.
            // For instance, if the alg is RS256, hash the access_token value with SHA-256, then take the left-most 128 bits and base64url encode them. The at_hash value is a case sensitive string.
            // If the ID Token is issued from the Authorization Endpoint with an access_token value, which is the case for the response_type value code id_token token, this is REQUIRED;
            // otherwise, its inclusion is OPTIONAL.
            var accessTokenHash = IdTokenLeftMostHasher.ComputeHash(createIdTokenRequest.AccessToken, signingCredentials.Algorithm);
            result.Add(new(DefaultJwtClaimTypes.AccessTokenHash, accessTokenHash));
        }

        if (!string.IsNullOrEmpty(createIdTokenRequest.AuthorizationCode))
        {
            // c_hash - Code hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the code value,
            // where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header.
            // For instance, if the alg is HS512, hash the code value with SHA-512, then take the left-most 256 bits and base64url encode them.
            // The c_hash value is a case sensitive string. If the ID Token is issued from the Authorization Endpoint with a code,
            // which is the case for the response_type values code id_token and code id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
            var authorizationCodeHash = IdTokenLeftMostHasher.ComputeHash(createIdTokenRequest.AuthorizationCode, signingCredentials.Algorithm);
            result.Add(new(DefaultJwtClaimTypes.AccessTokenHash, authorizationCodeHash));
        }

        foreach (var subjectClaim in GetSubjectClaims(createIdTokenRequest.UserAuthentication))
        {
            result.Add(subjectClaim);
        }

        var scopeClaimTypes = await GetIdTokenClaimTypesAllowedByScopesAsync(
            httpContext,
            createIdTokenRequest.AllowedResources,
            cancellationToken);
        if (createIdTokenRequest.Client.ShouldAlwaysIncludeUserClaimsInIdToken() || createIdTokenRequest.ForceIncludeUserClaimsInIdToken)
        {
            var profileClaims = await UserProfile.GetProfileClaimsAsync(
                httpContext,
                createIdTokenRequest.UserAuthentication,
                scopeClaimTypes,
                cancellationToken);
            foreach (var profileClaim in profileClaims)
            {
                if (scopeClaimTypes.Contains(profileClaim.Type) && !DefaultJwtClaimTypes.Restrictions.Contains(profileClaim.Type))
                {
                    result.Add(profileClaim);
                }
            }
        }

        return result;
    }

    public virtual async Task<HashSet<LightweightClaim>> GetAccessTokenClaimsAsync(
        HttpContext httpContext,
        CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createAccessTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createAccessTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var result = new HashSet<LightweightClaim>(256, LightweightClaim.EqualityComparer)
        {
            // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
            // iss - REQUIRED. Issuer Identifier for the Issuer of the response.
            // The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
            new(DefaultJwtClaimTypes.Issuer, createAccessTokenRequest.Issuer)
        };
        // aud - REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value.
        // It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings.
        // In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
        var audiences = await GetAccessTokenAudiencesAsync(httpContext, createAccessTokenRequest, cancellationToken);
        foreach (var audience in audiences)
        {
            result.Add(audience);
        }

        if (createAccessTokenRequest.Client.ShouldIncludeJwtIdIntoAccessToken() && createAccessTokenRequest.Client.GetAccessTokenFormat() == DefaultAccessTokenFormat.Jwt)
        {
            var jwtId = CryptoRandom.Create(16);
            result.Add(new(DefaultJwtClaimTypes.JwtId, jwtId));
        }

        if (createAccessTokenRequest.UserAuthentication != null)
        {
            foreach (var subjectClaim in GetSubjectClaims(createAccessTokenRequest.UserAuthentication))
            {
                result.Add(subjectClaim);
            }

            var scopeClaimTypes = await GetAccessTokenClaimTypesAllowedByScopesAsync(
                httpContext,
                createAccessTokenRequest.AllowedResources,
                cancellationToken);
            var profileClaims = await UserProfile.GetProfileClaimsAsync(
                httpContext,
                createAccessTokenRequest.UserAuthentication,
                scopeClaimTypes,
                cancellationToken);
            foreach (var profileClaim in profileClaims)
            {
                if (scopeClaimTypes.Contains(profileClaim.Type) && !DefaultJwtClaimTypes.Restrictions.Contains(profileClaim.Type))
                {
                    result.Add(profileClaim);
                }
            }
        }

        foreach (var scopeClaim in GetScopeClaims(createAccessTokenRequest.AllowedResources, createAccessTokenRequest.GrantType))
        {
            result.Add(scopeClaim);
        }

        return result;
    }

    protected virtual Task<IReadOnlySet<LightweightClaim>> GetIdTokenAudiencesAsync(
        HttpContext httpContext,
        CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createIdTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createIdTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var audiences = new HashSet<LightweightClaim>(LightweightClaim.EqualityComparer)
        {
            new(DefaultJwtClaimTypes.Audience, createIdTokenRequest.Client.GetClientId())
        };
        IReadOnlySet<LightweightClaim> result = audiences;
        return Task.FromResult(result);
    }

    protected virtual Task<IReadOnlySet<LightweightClaim>> GetAccessTokenAudiencesAsync(
        HttpContext httpContext,
        CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createAccessTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createAccessTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var audiences = new HashSet<LightweightClaim>(createAccessTokenRequest.AllowedResources.Resources.Count + 1, LightweightClaim.EqualityComparer)
        {
            new(DefaultJwtClaimTypes.Audience, createAccessTokenRequest.Client.GetClientId())
        };
        foreach (var resource in createAccessTokenRequest.AllowedResources.Resources)
        {
            audiences.Add(new(DefaultJwtClaimTypes.Audience, resource.GetProtocolName()));
        }

        if (FrameworkOptions.EmitStaticAudienceClaim)
        {
            var issuerAudience = new Uri(new(createAccessTokenRequest.Issuer, UriKind.Absolute), new Uri("resources", UriKind.Relative)).ToString();
            audiences.Add(new(DefaultJwtClaimTypes.Audience, issuerAudience));
        }

        IReadOnlySet<LightweightClaim> result = audiences;
        return Task.FromResult(result);
    }

    protected virtual Task<IReadOnlySet<string>> GetIdTokenClaimTypesAllowedByScopesAsync(
        HttpContext httpContext,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        cancellationToken.ThrowIfCancellationRequested();

        var additionalClaimTypes = new HashSet<string>(256);
        foreach (var idTokenScope in grantedResources.IdTokenScopes)
        {
            foreach (var idTokenScopeClaimType in idTokenScope.GetUserClaimTypes())
            {
                if (!DefaultJwtClaimTypes.Restrictions.Contains(idTokenScopeClaimType))
                {
                    additionalClaimTypes.Add(idTokenScopeClaimType);
                }
            }
        }

        IReadOnlySet<string> result = additionalClaimTypes;
        return Task.FromResult(result);
    }

    protected virtual Task<IReadOnlySet<string>> GetAccessTokenClaimTypesAllowedByScopesAsync(
        HttpContext httpContext,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        cancellationToken.ThrowIfCancellationRequested();

        var additionalClaimTypes = new HashSet<string>(256);
        foreach (var accessTokenScope in grantedResources.AccessTokenScopes)
        {
            foreach (var accessTokenScopeClaimType in accessTokenScope.GetUserClaimTypes())
            {
                if (!DefaultJwtClaimTypes.Restrictions.Contains(accessTokenScopeClaimType))
                {
                    additionalClaimTypes.Add(accessTokenScopeClaimType);
                }
            }
        }

        IReadOnlySet<string> result = additionalClaimTypes;
        return Task.FromResult(result);
    }

    protected virtual IEnumerable<LightweightClaim> GetScopeClaims(
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        string grantType)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);

        IEnumerable<string> scopes = grantedResources.RawScopes;
        if (grantType == DefaultGrantTypes.ClientCredentials && grantedResources.HasOfflineAccess)
        {
            scopes = grantedResources.RawScopes.Where(x => x != DefaultScopes.OfflineAccess);
        }

        foreach (var scope in scopes)
        {
            yield return new(DefaultJwtClaimTypes.Scope, scope);
        }
    }

    protected virtual IEnumerable<LightweightClaim> GetSubjectClaims(UserAuthentication userAuthentication)
    {
        ArgumentNullException.ThrowIfNull(userAuthentication);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // sub - REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
        // It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
        yield return new(DefaultJwtClaimTypes.Subject, userAuthentication.SubjectId);

        // https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.2.1
        // The sid (session ID) Claim used in ID Tokens and as a Logout Token parameter has the following definition
        // sid - OPTIONAL. Session ID - String identifier for a Session. This represents a Session of a User Agent or device for a logged-in End-User at an RP.
        // Different sid values are used to identify distinct sessions at an OP. The sid value need only be unique in the context of a particular issuer.
        // Its contents are opaque to the RP. Its syntax is the same as an OAuth 2.0 Client Identifier.
        yield return new(DefaultJwtClaimTypes.SessionId, userAuthentication.SessionId);

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // auth_time - Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
        // When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL.
        yield return new(
            DefaultJwtClaimTypes.AuthenticationTime,
            userAuthentication.AuthenticatedAt.ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64);
    }
}
