using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;
using OpenIdentityFramework.Services.Core.Models.IdTokenService;
using OpenIdentityFramework.Services.Core.Models.RefreshTokenService;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenResponseGenerator;

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
        IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode> authorizationCodes,
        IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> idTokens,
        IAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken> accessTokens,
        IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> refreshTokens)
    {
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(authorizationCodes);
        ArgumentNullException.ThrowIfNull(idTokens);
        ArgumentNullException.ThrowIfNull(accessTokens);
        ArgumentNullException.ThrowIfNull(refreshTokens);
        SystemClock = systemClock;
        AuthorizationCodes = authorizationCodes;
        IdTokens = idTokens;
        AccessTokens = accessTokens;
        RefreshTokens = refreshTokens;
    }

    protected ISystemClock SystemClock { get; }
    protected IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode> AuthorizationCodes { get; }
    protected IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> IdTokens { get; }
    protected IAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken> AccessTokens { get; }
    protected IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> RefreshTokens { get; }

    public virtual async Task<TokenResponseGenerationResult> CreateResponseAsync(
        TRequestContext requestContext,
        ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        if (request.GrantType == DefaultGrantTypes.AuthorizationCode)
        {
            if (request.AuthorizationCode is null || request.AuthorizationCodeHandle is null)
            {
                return new("Invalid request state");
            }

            return await CreateAuthorizationCodeResponseAsync(
                requestContext,
                request.AuthorizationCodeHandle,
                request.Client,
                request.AllowedResources,
                request.AuthorizationCode.GetUserAuthentication(),
                request.AuthorizationCode.GetNonce(),
                request.AuthorizationCode.GetState(),
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

        if (request.GrantType == DefaultGrantTypes.ClientCredentials)
        {
            if (request.RefreshTokenHandle is null || request.RefreshToken is null)
            {
                return new("Invalid request state");
            }

            return await CreateRefreshTokenResponseAsync(
                requestContext,
                request.Client,
                request.AllowedResources,
                request.RefreshTokenHandle,
                request.RefreshToken,
                request.Issuer,
                cancellationToken);
        }

        return new("Unsupported grant type");
    }


    protected virtual async Task<TokenResponseGenerationResult> CreateAuthorizationCodeResponseAsync(
        TRequestContext requestContext,
        string authorizationCodeHandle,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        UserAuthentication? userAuthentication,
        string? nonce,
        string? state,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(allowedResources);
        ArgumentNullException.ThrowIfNull(authorizationCodeHandle);
        cancellationToken.ThrowIfCancellationRequested();
        var issuedAt = SystemClock.UtcNow;
        var accessTokenRequest = new CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            DefaultGrantTypes.AuthorizationCode,
            client,
            issuer,
            allowedResources,
            userAuthentication,
            issuedAt);
        var accessTokenResult = await AccessTokens.CreateAccessTokenAsync(requestContext, accessTokenRequest, cancellationToken);
        if (accessTokenResult.HasError)
        {
            return new(accessTokenResult.ErrorDescription);
        }

        string? refreshToken = null;
        if (allowedResources.HasOfflineAccess)
        {
            string? referenceAccessTokenHandle = null;
            if (accessTokenResult.AccessToken.AccessTokenFormat == DefaultAccessTokenFormat.Reference)
            {
                referenceAccessTokenHandle = accessTokenResult.AccessToken.Handle;
            }

            var refreshTokenRequest = new CreateRefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                client,
                referenceAccessTokenHandle,
                issuer,
                allowedResources,
                userAuthentication,
                issuedAt);
            var refreshTokenResult = await RefreshTokens.CreateAsync(requestContext, refreshTokenRequest, cancellationToken);
            if (refreshTokenResult.HasError)
            {
                return new(refreshTokenResult.ErrorDescription);
            }

            refreshToken = refreshTokenResult.RefreshToken.Handle;
        }

        string? idToken = null;
        if (allowedResources.HasOpenId)
        {
            if (userAuthentication == null)
            {
                return new("User authentication can't be null when id_token requested via \"openid\" scope value");
            }

            var idTokenRequest = new CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                userAuthentication,
                client,
                allowedResources,
                nonce,
                state,
                issuer,
                issuedAt,
                accessTokenResult.AccessToken.Handle,
                authorizationCodeHandle,
                client.ShouldAlwaysIncludeUserClaimsInIdToken());
            var idTokenResult = await IdTokens.CreateIdTokenAsync(requestContext, idTokenRequest, cancellationToken);
            if (idTokenResult.HasError)
            {
                return new(idTokenResult.ErrorDescription);
            }

            idToken = idTokenResult.IdToken.Handle;
        }

        var resultScope = allowedResources.HasAnyScope() ? string.Join(' ', allowedResources.RawScopes) : null;
        await AuthorizationCodes.DeleteAsync(requestContext, authorizationCodeHandle, cancellationToken);
        var result = new SuccessfulTokenResponse(
            accessTokenResult.AccessToken.Handle,
            DefaultAccessTokenType.Bearer,
            refreshToken,
            accessTokenResult.AccessToken.LifetimeInSeconds,
            idToken,
            resultScope,
            issuer);
        return new(result);
    }

    protected virtual async Task<TokenResponseGenerationResult> CreateClientCredentialsResponseAsync(
        TRequestContext requestContext,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(allowedResources);
        cancellationToken.ThrowIfCancellationRequested();
        var issuedAt = SystemClock.UtcNow;
        var accessTokenRequest = new CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            DefaultGrantTypes.ClientCredentials,
            client,
            issuer,
            allowedResources,
            null,
            issuedAt);
        var accessTokenResult = await AccessTokens.CreateAccessTokenAsync(requestContext, accessTokenRequest, cancellationToken);
        if (accessTokenResult.HasError)
        {
            return new(accessTokenResult.ErrorDescription);
        }

        var resultScope = allowedResources.HasAnyScope() ? string.Join(' ', allowedResources.RawScopes) : null;
        var result = new SuccessfulTokenResponse(
            accessTokenResult.AccessToken.Handle,
            DefaultAccessTokenType.Bearer,
            null,
            accessTokenResult.AccessToken.LifetimeInSeconds,
            null,
            resultScope,
            issuer);
        return new(result);
    }

    protected virtual async Task<TokenResponseGenerationResult> CreateRefreshTokenResponseAsync(
        TRequestContext requestContext,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        string refreshTokenHandle,
        TRefreshToken refreshToken,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(allowedResources);
        ArgumentNullException.ThrowIfNull(refreshToken);
        cancellationToken.ThrowIfCancellationRequested();
        var issuedAt = SystemClock.UtcNow;
        var userAuthentication = refreshToken.GetUserAuthentication();
        var accessTokenRequest = new CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            DefaultGrantTypes.RefreshToken,
            client,
            issuer,
            allowedResources,
            userAuthentication,
            issuedAt);
        var accessTokenResult = await AccessTokens.CreateAccessTokenAsync(requestContext, accessTokenRequest, cancellationToken);
        if (accessTokenResult.HasError)
        {
            return new(accessTokenResult.ErrorDescription);
        }

        string? newRefreshTokenHandle = null;
        if (allowedResources.HasOfflineAccess)
        {
            string? newRefreshTokenReferenceAccessTokenHandle = null;
            if (accessTokenResult.AccessToken.AccessTokenFormat == DefaultAccessTokenFormat.Reference)
            {
                newRefreshTokenReferenceAccessTokenHandle = accessTokenResult.AccessToken.Handle;
            }

            var refreshTokenRequest = new CreateRefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                client,
                newRefreshTokenReferenceAccessTokenHandle,
                issuer,
                allowedResources,
                userAuthentication,
                issuedAt);
            var refreshTokenResult = await RefreshTokens.CreateAsync(requestContext, refreshTokenRequest, cancellationToken);
            if (refreshTokenResult.HasError)
            {
                return new(refreshTokenResult.ErrorDescription);
            }

            newRefreshTokenHandle = refreshTokenResult.RefreshToken.Handle;
        }

        string? idToken = null;
        if (allowedResources.HasOpenId)
        {
            var idTokenRequest = new CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                userAuthentication,
                client,
                allowedResources,
                null,
                null,
                issuer,
                issuedAt,
                accessTokenResult.AccessToken.Handle,
                null,
                client.ShouldAlwaysIncludeUserClaimsInIdToken());
            var idTokenResult = await IdTokens.CreateIdTokenAsync(requestContext, idTokenRequest, cancellationToken);
            if (idTokenResult.HasError)
            {
                return new(idTokenResult.ErrorDescription);
            }

            idToken = idTokenResult.IdToken.Handle;
        }

        var resultScope = allowedResources.HasAnyScope() ? string.Join(' ', allowedResources.RawScopes) : null;
        await RefreshTokens.DeleteAsync(requestContext, refreshTokenHandle, cancellationToken);
        var previousAccessTokenHandle = refreshToken.GetReferenceAccessTokenHandle();
        if (previousAccessTokenHandle is not null)
        {
            await AccessTokens.DeleteAsync(requestContext, previousAccessTokenHandle, cancellationToken);
        }

        var result = new SuccessfulTokenResponse(
            accessTokenResult.AccessToken.Handle,
            DefaultAccessTokenType.Bearer,
            newRefreshTokenHandle,
            accessTokenResult.AccessToken.LifetimeInSeconds,
            idToken,
            resultScope,
            issuer);
        return new(result);
    }
}
