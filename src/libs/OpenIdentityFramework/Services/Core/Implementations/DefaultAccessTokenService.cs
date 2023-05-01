using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultAccessTokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken>
    : IAccessTokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAccessToken : AbstractAccessToken
{
    public DefaultAccessTokenService(
        ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret> tokenClaims,
        IKeyMaterialService keyMaterial,
        IJwtService jwtService,
        IAccessTokenStorage accessTokenStorage)
    {
        ArgumentNullException.ThrowIfNull(tokenClaims);
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentNullException.ThrowIfNull(jwtService);
        ArgumentNullException.ThrowIfNull(accessTokenStorage);
        TokenClaims = tokenClaims;
        KeyMaterial = keyMaterial;
        JwtService = jwtService;
        AccessTokenStorage = accessTokenStorage;
    }

    protected ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret> TokenClaims { get; }
    protected IKeyMaterialService KeyMaterial { get; }
    protected IJwtService JwtService { get; }
    protected IAccessTokenStorage AccessTokenStorage { get; }

    public async Task<AccessTokenCreationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> CreateAccessTokenAsync(
        HttpContext httpContext,
        CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createAccessTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createAccessTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var claims = await TokenClaims.GetAccessTokenClaimsAsync(
            httpContext,
            createAccessTokenRequest,
            cancellationToken);
        var accessTokenFormat = createAccessTokenRequest.Client.GetAccessTokenFormat();
        var accessTokenLifetime = createAccessTokenRequest.Client.GetAccessTokenLifetime();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(createAccessTokenRequest.IssuedAt.ToUnixTimeSeconds());
        var expiresAt = issuedAt.Add(accessTokenLifetime);
        string accessToken;
        if (accessTokenFormat == DefaultAccessTokenFormat.Jwt)
        {
            var signingCredentials = await KeyMaterial.GetSigningCredentialsAsync(httpContext, createAccessTokenRequest.Issuer, createAccessTokenRequest.Client.GetAllowedIdTokenSigningAlgorithms(), cancellationToken);
            accessToken = await JwtService.CreateAccessTokenAsync(
                httpContext,
                signingCredentials,
                issuedAt,
                expiresAt,
                claims,
                cancellationToken);
        }
        else if (accessTokenFormat == DefaultAccessTokenFormat.Reference)
        {
            accessToken = await AccessTokenStorage.CreateAsync(
                httpContext,
                createAccessTokenRequest.Issuer,
                createAccessTokenRequest.Client.GetClientId(),
                createAccessTokenRequest.UserAuthentication,
                createAccessTokenRequest.AllowedResources.RawScopes,
                claims,
                issuedAt,
                expiresAt,
                cancellationToken);
        }
        else
        {
            return new("Unsupported access token format");
        }

        var lifetime = Convert.ToInt64(expiresAt.Subtract(issuedAt).TotalSeconds);
        return new(new CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            accessTokenFormat,
            createAccessTokenRequest.Issuer,
            createAccessTokenRequest.Client,
            createAccessTokenRequest.UserAuthentication,
            createAccessTokenRequest.AllowedResources,
            claims,
            issuedAt,
            expiresAt,
            lifetime,
            accessToken));
    }

    public Task DeleteAsync(HttpContext httpContext, string accessTokenHandle, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
