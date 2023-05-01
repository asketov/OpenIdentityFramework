using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.TokenService;
using OpenIdentityFramework.Services.Cryptography;
using OpenIdentityFramework.Storages.Operation;

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
        OpenIdentityFrameworkOptions frameworkOptions,
        ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret> tokenClaims,
        IKeyMaterialService keyMaterial,
        IIdTokenLeftMostHasher idTokenLeftMostHasher,
        IJwtService jwtService,
        IAccessTokenStorage accessTokenStorage)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(tokenClaims);
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentNullException.ThrowIfNull(idTokenLeftMostHasher);
        ArgumentNullException.ThrowIfNull(jwtService);
        ArgumentNullException.ThrowIfNull(accessTokenStorage);
        FrameworkOptions = frameworkOptions;
        TokenClaims = tokenClaims;
        KeyMaterial = keyMaterial;
        IdTokenLeftMostHasher = idTokenLeftMostHasher;
        JwtService = jwtService;
        AccessTokenStorage = accessTokenStorage;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret> TokenClaims { get; }
    protected IKeyMaterialService KeyMaterial { get; }
    protected IIdTokenLeftMostHasher IdTokenLeftMostHasher { get; }
    protected IJwtService JwtService { get; }
    protected IAccessTokenStorage AccessTokenStorage { get; }

    public virtual async Task<string> CreateIdTokenAsync(
        HttpContext httpContext,
        IdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> idTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(idTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var signingCredentials = await KeyMaterial.GetSigningCredentialsAsync(httpContext, idTokenRequest.Issuer, idTokenRequest.Client.GetAllowedIdTokenSigningAlgorithms(), cancellationToken);
        var claims = await TokenClaims.GetIdentityTokenClaimsAsync(httpContext, idTokenRequest, signingCredentials, cancellationToken);
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(idTokenRequest.IssuedAt.ToUnixTimeSeconds());
        var expiresAt = issuedAt.Add(idTokenRequest.Client.GetIdTokenLifetime());
        return await JwtService.CreateIdTokenAsync(
            httpContext,
            signingCredentials,
            issuedAt,
            expiresAt,
            claims,
            cancellationToken);
    }

    public virtual async Task<AccessTokenResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> CreateAccessTokenAsync(
        HttpContext httpContext,
        AccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> accessTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accessTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var claims = await TokenClaims.GetAccessTokenClaimsAsync(
            httpContext,
            accessTokenRequest,
            cancellationToken);
        var accessTokenType = accessTokenRequest.Client.GetAccessTokenType();
        var accessTokenLifetime = accessTokenRequest.Client.GetAccessTokenLifetime();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(accessTokenRequest.IssuedAt.ToUnixTimeSeconds());
        var expiresAt = issuedAt.Add(accessTokenLifetime);
        string accessToken;
        if (accessTokenType == DefaultAccessTokenType.Jwt)
        {
            var signingCredentials = await KeyMaterial.GetSigningCredentialsAsync(httpContext, accessTokenRequest.Issuer, accessTokenRequest.Client.GetAllowedIdTokenSigningAlgorithms(), cancellationToken);
            accessToken = await JwtService.CreateAccessTokenAsync(
                httpContext,
                signingCredentials,
                issuedAt,
                expiresAt,
                claims,
                cancellationToken);
        }
        else if (accessTokenType == DefaultAccessTokenType.Reference)
        {
            accessToken = await AccessTokenStorage.CreateAsync(
                httpContext,
                accessTokenRequest.Issuer,
                accessTokenRequest.Client.GetClientId(),
                accessTokenRequest.UserAuthentication,
                accessTokenRequest.RequestedResources.RawScopes,
                claims,
                issuedAt,
                expiresAt,
                cancellationToken);
        }
        else
        {
            throw new InvalidOperationException("Unsupported access token type!");
        }

        var lifetime = Convert.ToInt64(expiresAt.Subtract(issuedAt).TotalSeconds);
        return new(
            accessTokenType,
            accessTokenRequest.Issuer,
            accessTokenRequest.GrantType,
            accessTokenRequest.Client,
            accessTokenRequest.UserAuthentication,
            accessTokenRequest.RequestedResources,
            claims,
            issuedAt,
            expiresAt,
            lifetime,
            accessToken);
    }

    public Task<string> CreateRefreshTokenAsync(
        HttpContext httpContext,
        RefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> refreshTokenRequest,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
