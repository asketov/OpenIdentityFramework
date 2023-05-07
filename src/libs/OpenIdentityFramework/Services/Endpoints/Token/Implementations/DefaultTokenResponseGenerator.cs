using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenResponseGenerator;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations;

public class DefaultTokenResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TAccessToken, TRefreshToken>
    : ITokenResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
    where TAccessToken : AbstractAccessToken
    where TRefreshToken : AbstractRefreshToken
{
    public DefaultTokenResponseGenerator(
        ISystemClock systemClock,
        IAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken> accessTokenService,
        IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> idTokenService,
        IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> refreshTokenService)
    {
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(accessTokenService);
        ArgumentNullException.ThrowIfNull(idTokenService);
        ArgumentNullException.ThrowIfNull(refreshTokenService);
        SystemClock = systemClock;
        AccessTokenService = accessTokenService;
        IdTokenService = idTokenService;
        RefreshTokenService = refreshTokenService;
    }

    protected ISystemClock SystemClock { get; }
    protected IAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken> AccessTokenService { get; }
    protected IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> IdTokenService { get; }
    protected IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> RefreshTokenService { get; }

    public virtual async Task<TokenResponseGenerationResult> CreateResponseAsync(
        TRequestContext requestContext,
        ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        if (request.GrantType == DefaultGrantTypes.AuthorizationCode)
        {
            if (request.AuthorizationCode is null || request.ResourceOwnerProfile is null)
            {
                return new("Invalid request state");
            }

            return await CreateAuthorizationCodeResponseAsync(
                requestContext,
                request.Client,
                request.AllowedResources,
                request.AuthorizationCode,
                request.ResourceOwnerProfile,
                request.Issuer,
                cancellationToken);
        }

        if (request.GrantType == DefaultGrantTypes.ClientCredentials)
        {
            return await CreateClientCredentialsResponseAsync(
                requestContext,
                request.Client,
                request.AllowedResources,
                request.Issuer,
                cancellationToken);
        }

        if (request.GrantType == DefaultGrantTypes.RefreshToken)
        {
            if (request.RefreshToken is null)
            {
                return new("Invalid request state");
            }

            return await CreateRefreshTokenResponseAsync(
                requestContext,
                request.Client,
                request.AllowedResources,
                request.RefreshToken,
                request.ResourceOwnerProfile,
                request.Issuer,
                cancellationToken);
        }

        return new("Unsupported grant type");
    }


    protected virtual async Task<TokenResponseGenerationResult> CreateAuthorizationCodeResponseAsync(
        TRequestContext requestContext,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        ValidAuthorizationCode<TAuthorizationCode> authorizationCode,
        ResourceOwnerProfile resourceOwnerProfile,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizationCode);
        ArgumentNullException.ThrowIfNull(grantedResources);
        ArgumentNullException.ThrowIfNull(resourceOwnerProfile);
        cancellationToken.ThrowIfCancellationRequested();
        var accessTokenResult = await AccessTokenService.CreateAccessTokenAsync(
            requestContext,
            client,
            issuer,
            DefaultGrantTypes.AuthorizationCode,
            resourceOwnerProfile,
            grantedResources,
            SystemClock.UtcNow,
            cancellationToken);
        if (accessTokenResult.HasError)
        {
            return new(accessTokenResult.ErrorDescription);
        }

        string? idTokenHandle = null;
        if (grantedResources.HasOpenId)
        {
            var idTokenResult = await IdTokenService.CreateIdTokenAsync(
                requestContext,
                client,
                issuer,
                null,
                accessTokenResult.AccessToken.Handle,
                null,
                resourceOwnerProfile,
                grantedResources,
                accessTokenResult.AccessToken.ActualIssuedAt,
                cancellationToken);
            if (idTokenResult.HasError)
            {
                return new(idTokenResult.ErrorDescription);
            }

            idTokenHandle = idTokenResult.IdToken.Handle;
        }

        string? refreshTokenHandle = null;
        if (grantedResources.HasOfflineAccess)
        {
            var refreshTokenResult = await RefreshTokenService.CreateAsync(
                requestContext,
                issuer,
                null,
                accessTokenResult.AccessToken,
                cancellationToken);
            if (refreshTokenResult.HasError)
            {
                return new(refreshTokenResult.ErrorDescription);
            }

            refreshTokenHandle = refreshTokenResult.RefreshToken.Handle;
        }

        var resultScope = grantedResources.HasAnyScope() ? string.Join(' ', grantedResources.RawScopes) : null;
        var successfulResponse = new SuccessfulTokenResponse(
            accessTokenResult.AccessToken.Handle,
            DefaultAccessTokenType.Bearer,
            refreshTokenHandle,
            accessTokenResult.AccessToken.LifetimeInSeconds,
            idTokenHandle,
            resultScope,
            issuer);
        return new(successfulResponse);
    }

    protected virtual async Task<TokenResponseGenerationResult> CreateClientCredentialsResponseAsync(
        TRequestContext requestContext,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        cancellationToken.ThrowIfCancellationRequested();
        var accessTokenResult = await AccessTokenService.CreateAccessTokenAsync(
            requestContext,
            client,
            issuer,
            DefaultGrantTypes.ClientCredentials,
            null,
            grantedResources,
            SystemClock.UtcNow,
            cancellationToken);
        if (accessTokenResult.HasError)
        {
            return new(accessTokenResult.ErrorDescription);
        }

        var resultScope = grantedResources.HasAnyScope() ? string.Join(' ', grantedResources.RawScopes) : null;
        var successfulResponse = new SuccessfulTokenResponse(
            accessTokenResult.AccessToken.Handle,
            DefaultAccessTokenType.Bearer,
            null,
            accessTokenResult.AccessToken.LifetimeInSeconds,
            null,
            resultScope,
            issuer);
        return new(successfulResponse);
    }

    protected virtual async Task<TokenResponseGenerationResult> CreateRefreshTokenResponseAsync(
        TRequestContext requestContext,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        ValidRefreshToken<TRefreshToken> refreshToken,
        ResourceOwnerProfile? resourceOwnerProfile,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        cancellationToken.ThrowIfCancellationRequested();
        var accessTokenResult = await AccessTokenService.CreateAccessTokenAsync(
            requestContext,
            client,
            issuer,
            DefaultGrantTypes.RefreshToken,
            resourceOwnerProfile,
            grantedResources,
            SystemClock.UtcNow,
            cancellationToken);
        if (accessTokenResult.HasError)
        {
            return new(accessTokenResult.ErrorDescription);
        }

        string? idTokenHandle = null;
        if (grantedResources.HasOpenId)
        {
            if (resourceOwnerProfile is null)
            {
                return new("Invalid request state");
            }

            var idTokenResult = await IdTokenService.CreateIdTokenAsync(
                requestContext,
                client,
                issuer,
                null,
                accessTokenResult.AccessToken.Handle,
                null,
                resourceOwnerProfile,
                grantedResources,
                accessTokenResult.AccessToken.ActualIssuedAt,
                cancellationToken);
            if (idTokenResult.HasError)
            {
                return new(idTokenResult.ErrorDescription);
            }

            idTokenHandle = idTokenResult.IdToken.Handle;
        }

        string? refreshTokenHandle = null;
        if (grantedResources.HasOfflineAccess)
        {
            var refreshTokenResult = await RefreshTokenService.CreateAsync(
                requestContext,
                issuer,
                refreshToken,
                accessTokenResult.AccessToken,
                cancellationToken);
            if (refreshTokenResult.HasError)
            {
                return new(refreshTokenResult.ErrorDescription);
            }

            refreshTokenHandle = refreshTokenResult.RefreshToken.Handle;
        }

        var resultScope = grantedResources.HasAnyScope() ? string.Join(' ', grantedResources.RawScopes) : null;
        var successfulResponse = new SuccessfulTokenResponse(
            accessTokenResult.AccessToken.Handle,
            DefaultAccessTokenType.Bearer,
            refreshTokenHandle,
            accessTokenResult.AccessToken.LifetimeInSeconds,
            idTokenHandle,
            resultScope,
            issuer);
        return new(successfulResponse);
    }
}
