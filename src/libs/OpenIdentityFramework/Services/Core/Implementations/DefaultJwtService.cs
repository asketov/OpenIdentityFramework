using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultJwtService : IJwtService
{
    public DefaultJwtService(OpenIdentityFrameworkOptions frameworkOptions)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        FrameworkOptions = frameworkOptions;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    public Task<string> CreateIdTokenAsync(
        HttpContext httpContext,
        SigningCredentials signingCredentials,
        string issuer,
        IReadOnlySet<string> audiences,
        DateTimeOffset createdAt,
        TimeSpan lifetime,
        IReadOnlySet<LightweightClaim> claims,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var header = CreateIdTokenHeader(signingCredentials);
        var payload = CreatePayload(
            issuer,
            audiences,
            createdAt,
            lifetime,
            claims,
            true);
        var handler = new JsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };
        var idToken = handler.CreateToken(payload, signingCredentials, header);
        return Task.FromResult(idToken);
    }

    protected virtual Dictionary<string, object> CreateIdTokenHeader(SigningCredentials credentials)
    {
        var header = new Dictionary<string, object>();
        // emit x5t claim for backwards compatibility with v4 of MS JWT library
        AddGetCertHashToHeaderIfRequired(header, credentials);
        return header;
    }

    protected virtual void AddGetCertHashToHeaderIfRequired(
        Dictionary<string, object> header,
        SigningCredentials credentials)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(credentials);
        if (credentials.Key is X509SecurityKey x509Key)
        {
            var cert = x509Key.Certificate;
            header["x5t"] = WebEncoders.Base64UrlEncode(cert.GetCertHash());
        }
    }

    protected virtual string CreatePayload(
        string issuer,
        IReadOnlySet<string> audiences,
        DateTimeOffset createdAt,
        TimeSpan lifetime,
        IReadOnlySet<LightweightClaim> claims,
        bool requireSubject)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(audiences);
        ArgumentNullException.ThrowIfNull(claims);
        var payload = new Dictionary<string, object>(claims.Count + audiences.Count + 16)
        {
            // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
            // iss - REQUIRED. Issuer Identifier for the Issuer of the response.
            // The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
            { DefaultJwtClaimTypes.Issuer, issuer }
        };
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // sub - REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client,
        // e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
        // It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
        var subject = requireSubject
            ? claims.Single(x => x.Type == DefaultJwtClaimTypes.Subject)
            : claims.SingleOrDefault(x => x.Type == DefaultJwtClaimTypes.Subject);
        if (subject != null)
        {
            payload.Add(DefaultJwtClaimTypes.Subject, subject.Value);
        }

        // aud - REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value.
        // It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings.
        // In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
        if (audiences.Count > 0)
        {
            if (audiences.Count == 1)
            {
                payload.Add(DefaultJwtClaimTypes.Audience, audiences.Single());
            }
            else
            {
                payload.Add(DefaultJwtClaimTypes.Audience, audiences);
            }
        }

        var createdAtUnixTime = createdAt.ToUnixTimeSeconds();
        var expiresAtUnixTime = createdAt.Add(lifetime).ToUnixTimeSeconds();
        // exp - REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
        // The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value.
        // Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
        // Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
        payload.Add(DefaultJwtClaimTypes.Expiration, expiresAtUnixTime);

        // iat - REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
        payload.Add(DefaultJwtClaimTypes.IssuedAt, createdAtUnixTime);

        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
        // "nbf" (Not Before) Claim - The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
        payload.Add(DefaultJwtClaimTypes.NotBefore, createdAtUnixTime);

        // scope
        var scopeClaims = claims.Where(x => x.Type == DefaultJwtClaimTypes.Scope).Select(x => x.Value).ToHashSet();
        if (scopeClaims.Count > 0)
        {
            if (FrameworkOptions.EmitScopesAsSpaceDelimitedStringInJwt)
            {
                payload.Add(DefaultJwtClaimTypes.Scope, string.Join(" ", scopeClaims));
            }
            else
            {
                payload.Add(DefaultJwtClaimTypes.Scope, scopeClaims);
            }
        }

        // amr - OPTIONAL. Authentication Methods References. JSON array of strings that are identifiers for authentication methods used in the authentication.
        var amrClaims = claims.Where(x => x.Type == DefaultJwtClaimTypes.AuthenticationMethod).Select(x => x.Value).ToHashSet();
        if (amrClaims.Count > 0)
        {
            payload.Add(DefaultJwtClaimTypes.AuthenticationMethod, amrClaims);
        }

        // remain claims
        var remainClaimTypes = claims
            .Where(x => x.Type != DefaultJwtClaimTypes.Subject && x.Type != DefaultJwtClaimTypes.Scope && x.Type != DefaultJwtClaimTypes.AuthenticationMethod)
            .Select(x => x.Type)
            .Distinct();
        foreach (var claimType in remainClaimTypes)
        {
            if (!payload.ContainsKey(claimType))
            {
                var claimsOfType = claims.Where(x => x.Type == claimType).ToList();
                if (claimsOfType.Count == 1)
                {
                    var claimValue = GetValue(claimsOfType.Single());
                    payload.Add(claimType, claimValue);
                }
                else
                {
                    var claimValues = GetValues(claimsOfType);
                    payload.Add(claimType, claimValues);
                }
            }
        }

        return JsonSerializer.Serialize(payload);
    }

    protected virtual object GetValue(LightweightClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        return claim.ValueType switch
        {
            ClaimValueTypes.Boolean => bool.Parse(claim.Value),
            ClaimValueTypes.Integer => int.Parse(claim.Value, CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer32 => int.Parse(claim.Value, CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64 => long.Parse(claim.Value, CultureInfo.InvariantCulture),
            ClaimValueTypes.UInteger32 => uint.Parse(claim.Value, CultureInfo.InvariantCulture),
            ClaimValueTypes.UInteger64 => ulong.Parse(claim.Value, CultureInfo.InvariantCulture),
            ClaimValueTypes.DateTime => DateTime.Parse(claim.Value, CultureInfo.InvariantCulture),
            DefaultClaimValueTypes.Json => JsonSerializer.Deserialize<JsonElement>(claim.Value),
            _ => claim.Value
        };
    }

    protected virtual IEnumerable<object> GetValues(IReadOnlyCollection<LightweightClaim> claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        foreach (var claim in claims)
        {
            yield return GetValue(claim);
        }
    }
}
