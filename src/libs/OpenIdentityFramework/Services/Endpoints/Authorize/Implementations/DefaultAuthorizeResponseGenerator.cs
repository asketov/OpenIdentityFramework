using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Requests.Authorize;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.TokenService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : IAuthorizeResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultAuthorizeResponseGenerator(
        ISystemClock systemClock,
        IAuthorizationCodeService<TClient, TClientSecret> authorizationCodeService,
        ITokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret> tokensService)
    {
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(authorizationCodeService);
        ArgumentNullException.ThrowIfNull(tokensService);
        SystemClock = systemClock;
        AuthorizationCodeService = authorizationCodeService;
        TokensService = tokensService;
    }

    protected ISystemClock SystemClock { get; }
    protected IAuthorizationCodeService<TClient, TClientSecret> AuthorizationCodeService { get; }
    protected ITokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret> TokensService { get; }

    public virtual async Task<AuthorizeResponse> CreateResponseAsync(
        HttpContext httpContext,
        ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret> request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(SystemClock.UtcNow.ToUnixTimeSeconds());
        var codeRequest = new AuthorizationCodeRequest<TClient, TClientSecret>(
            request.Ticket.UserAuthentication,
            request.AuthorizeRequest.Client,
            request.AuthorizeRequest.RedirectUri,
            request.GrantedResources.RawScopes,
            request.AuthorizeRequest.CodeChallenge,
            request.AuthorizeRequest.CodeChallengeMethod,
            request.AuthorizeRequest.Nonce,
            request.AuthorizeRequest.State,
            request.AuthorizeRequest.Issuer,
            issuedAt);
        var authorizationCode = await AuthorizationCodeService.CreateAsync(httpContext, codeRequest, cancellationToken);
        string? idToken = null;
        if (request.AuthorizeRequest.GrantType == DefaultGrantTypes.Hybrid && request.AuthorizeRequest.ResponseType == ResponseType.CodeIdToken)
        {
            var idTokenRequest = new IdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                request.Ticket,
                request.AuthorizeRequest.Client,
                request.AuthorizeRequest.RedirectUri,
                request.GrantedResources,
                request.AuthorizeRequest.Nonce,
                request.AuthorizeRequest.State,
                request.AuthorizeRequest.Issuer,
                issuedAt,
                null,
                authorizationCode,
                false);
            idToken = await TokensService.CreateIdTokenAsync(httpContext, idTokenRequest, cancellationToken);
        }

        return new(authorizationCode, request.AuthorizeRequest.State, request.AuthorizeRequest.Issuer, idToken);
    }
}
