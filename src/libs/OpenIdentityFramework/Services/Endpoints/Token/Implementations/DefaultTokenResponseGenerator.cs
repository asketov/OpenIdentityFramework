using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.TokenService;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenResponseGenerator;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations;

public class DefaultTokenResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    : ITokenResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public DefaultTokenResponseGenerator(ISystemClock systemClock, ITokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret> tokens)
    {
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(tokens);
        SystemClock = systemClock;
        Tokens = tokens;
    }

    protected ISystemClock SystemClock { get; }
    protected ITokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret> Tokens { get; }

    public virtual async Task<TokenResponse> CreateResponseAsync(
        HttpContext httpContext,
        ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        if (request.GrantType == DefaultGrantTypes.AuthorizationCode)
        {
            if (!request.IsAuthorizationCodeGrant)
            {
                throw new ArgumentException("Invalid request state!", nameof(request));
            }

            return await CreateAuthorizationCodeResponseAsync(
                httpContext,
                request.AuthorizationCodeHandle,
                request.Client,
                request.RequestedResources,
                request.AuthorizationCode.GetUserAuthentication(),
                request.AuthorizationCode.GetNonce(),
                request.AuthorizationCode.GetState(),
                request.Issuer,
                cancellationToken);
        }

        throw new InvalidOperationException("Unsupported grant type!");
    }

    protected virtual async Task<TokenResponse> CreateAuthorizationCodeResponseAsync(
        HttpContext httpContext,
        string authorizationCode,
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        UserAuthentication? userAuthentication,
        string? nonce,
        string? state,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(requestedResources);
        ArgumentNullException.ThrowIfNull(authorizationCode);
        cancellationToken.ThrowIfCancellationRequested();
        var issuedAt = SystemClock.UtcNow;
        var accessTokenRequest = new AccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            DefaultGrantTypes.AuthorizationCode,
            client,
            issuer,
            requestedResources,
            userAuthentication,
            issuedAt);
        var accessTokenResult = await Tokens.CreateAccessTokenAsync(httpContext, accessTokenRequest, cancellationToken);
        string? refreshToken = null;
        if (requestedResources.HasOfflineAccess)
        {
            string? referenceAccessTokenHandle = null;
            if (accessTokenResult.AccessTokenType == DefaultAccessTokenType.Reference)
            {
                referenceAccessTokenHandle = accessTokenResult.Handle;
            }

            var refreshTokenRequest = new RefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                client,
                referenceAccessTokenHandle,
                issuer,
                requestedResources,
                userAuthentication,
                issuedAt);
            refreshToken = await Tokens.CreateRefreshTokenAsync(httpContext, refreshTokenRequest, cancellationToken);
        }

        string? idToken = null;
        if (requestedResources.HasOpenId)
        {
            if (userAuthentication == null)
            {
                throw new ArgumentNullException(nameof(userAuthentication), "User authentication can't be null when id_token requested via \"openid\" scope value");
            }

            var idTokenRequest = new IdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                userAuthentication,
                client,
                requestedResources,
                nonce,
                state,
                issuer,
                issuedAt,
                accessTokenResult.Handle,
                authorizationCode,
                client.ShouldAlwaysIncludeUserClaimsInIdToken());
            idToken = await Tokens.CreateIdTokenAsync(httpContext, idTokenRequest, cancellationToken);
        }

        var resultScope = requestedResources.HasAnyScope() ? string.Join(' ', requestedResources.RawScopes) : null;

        return new(
            accessTokenResult.Handle,
            DefaultIssuedTokenType.Bearer,
            refreshToken,
            accessTokenResult.LifetimeInSeconds,
            idToken,
            resultScope,
            issuer);
    }
}
