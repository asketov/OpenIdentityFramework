using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken>
    : IAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAccessToken : AbstractAccessToken
{
    public DefaultAccessTokenService(
        ITokenClaimsService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> tokenClaims,
        IKeyMaterialService<TRequestContext> keyMaterial,
        IJwtService<TRequestContext> jwtService,
        IAccessTokenStorage<TRequestContext, TAccessToken> accessTokenStorage)
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

    protected ITokenClaimsService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> TokenClaims { get; }
    protected IKeyMaterialService<TRequestContext> KeyMaterial { get; }
    protected IJwtService<TRequestContext> JwtService { get; }
    protected IAccessTokenStorage<TRequestContext, TAccessToken> AccessTokenStorage { get; }

    public virtual async Task<AccessTokenCreationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> CreateAccessTokenAsync(
        TRequestContext requestContext,
        CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createAccessTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createAccessTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var claims = await TokenClaims.GetAccessTokenClaimsAsync(
            requestContext,
            createAccessTokenRequest,
            cancellationToken);
        var accessTokenFormat = createAccessTokenRequest.Client.GetAccessTokenFormat();
        var accessTokenLifetime = createAccessTokenRequest.Client.GetAccessTokenLifetime();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(createAccessTokenRequest.IssuedAt.ToUnixTimeSeconds());
        var expiresAt = issuedAt.Add(accessTokenLifetime);
        string accessToken;
        if (accessTokenFormat == DefaultAccessTokenFormat.Jwt)
        {
            var signingCredentials = await KeyMaterial.GetSigningCredentialsAsync(requestContext, createAccessTokenRequest.Issuer, createAccessTokenRequest.Client.GetAllowedIdTokenSigningAlgorithms(), cancellationToken);
            accessToken = await JwtService.CreateAccessTokenAsync(
                requestContext,
                signingCredentials,
                issuedAt,
                expiresAt,
                claims,
                cancellationToken);
        }
        else if (accessTokenFormat == DefaultAccessTokenFormat.Reference)
        {
            accessToken = await AccessTokenStorage.CreateAsync(
                requestContext,
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

    public virtual async Task DeleteAsync(
        TRequestContext requestContext,
        string accessTokenHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await AccessTokenStorage.DeleteAsync(requestContext, accessTokenHandle, cancellationToken);
    }
}
