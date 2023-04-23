using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.TokenService;
using OpenIdentityFramework.Services.Cryptography;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultTokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret> :
    ITokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultTokenService(
        ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret> tokenClaims,
        IKeyMaterialService keyMaterial,
        IIdTokenLeftMostHasher idTokenLeftMostHasher,
        IJwtService jwtService)
    {
        ArgumentNullException.ThrowIfNull(tokenClaims);
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentNullException.ThrowIfNull(idTokenLeftMostHasher);
        ArgumentNullException.ThrowIfNull(jwtService);
        TokenClaims = tokenClaims;
        KeyMaterial = keyMaterial;
        IdTokenLeftMostHasher = idTokenLeftMostHasher;
        JwtService = jwtService;
    }

    protected ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret> TokenClaims { get; }
    protected IKeyMaterialService KeyMaterial { get; }
    protected IIdTokenLeftMostHasher IdTokenLeftMostHasher { get; }
    protected IJwtService JwtService { get; }

    public virtual async Task<string> CreateIdTokenAsync(
        HttpContext httpContext,
        IdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> idTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(idTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var claims = await TokenClaims.GetIdentityTokenClaimsAsync(httpContext, idTokenRequest, cancellationToken);
        var audiences = new HashSet<string>(1)
        {
            idTokenRequest.Client.GetClientId()
        };
        if (idTokenRequest.Nonce != null)
        {
            claims.Add(new(DefaultJwtClaimTypes.Nonce, idTokenRequest.Nonce));
        }

        var signingCredentials = await KeyMaterial.GetSigningCredentialsAsync(httpContext, idTokenRequest.Issuer, idTokenRequest.Client.GetAllowedIdTokenSigningAlgorithms(), cancellationToken);
        if (!string.IsNullOrEmpty(idTokenRequest.AccessToken))
        {
            // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11
            // at_hash - Access Token hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the access_token value,
            // where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header.
            // For instance, if the alg is RS256, hash the access_token value with SHA-256, then take the left-most 128 bits and base64url encode them. The at_hash value is a case sensitive string.
            // If the ID Token is issued from the Authorization Endpoint with an access_token value, which is the case for the response_type value code id_token token, this is REQUIRED;
            // otherwise, its inclusion is OPTIONAL.
            var accessTokenHash = IdTokenLeftMostHasher.ComputeHash(idTokenRequest.AccessToken, signingCredentials.Algorithm);
            claims.Add(new(DefaultJwtClaimTypes.AccessTokenHash, accessTokenHash));
        }

        if (!string.IsNullOrEmpty(idTokenRequest.AuthorizationCode))
        {
            // c_hash - Code hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the code value,
            // where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header.
            // For instance, if the alg is HS512, hash the code value with SHA-512, then take the left-most 256 bits and base64url encode them.
            // The c_hash value is a case sensitive string. If the ID Token is issued from the Authorization Endpoint with a code,
            // which is the case for the response_type values code id_token and code id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
            var authorizationCodeHash = IdTokenLeftMostHasher.ComputeHash(idTokenRequest.AuthorizationCode, signingCredentials.Algorithm);
            claims.Add(new(DefaultJwtClaimTypes.AuthorizationCodeHash, authorizationCodeHash));
        }

        return await JwtService.CreateIdTokenAsync(
            httpContext,
            signingCredentials,
            idTokenRequest.Issuer,
            audiences,
            idTokenRequest.IssuedAt,
            idTokenRequest.Client.GetIdTokenLifetime(),
            claims,
            cancellationToken);
    }
}
