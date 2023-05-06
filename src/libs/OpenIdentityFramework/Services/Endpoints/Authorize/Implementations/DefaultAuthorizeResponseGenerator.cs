using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.IdTokenService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    : IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public DefaultAuthorizeResponseGenerator(
        ISystemClock systemClock,
        IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode> authorizationCodeService,
        IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> idTokenService)
    {
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(authorizationCodeService);
        ArgumentNullException.ThrowIfNull(idTokenService);
        SystemClock = systemClock;
        AuthorizationCodeService = authorizationCodeService;
        IdTokenService = idTokenService;
    }

    protected ISystemClock SystemClock { get; }
    protected IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode> AuthorizationCodeService { get; }
    protected IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> IdTokenService { get; }

    public virtual async Task<AuthorizeResponseGenerationResult> CreateResponseAsync(
        TRequestContext requestContext,
        ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret> request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(SystemClock.UtcNow.ToUnixTimeSeconds());
        var codeRequest = new CreateAuthorizationCodeRequest<TClient, TClientSecret>(
            request.Ticket.UserAuthentication,
            request.AuthorizeRequest.Client,
            request.AuthorizeRequest.AuthorizeRequestRedirectUri,
            request.GrantedResources.RawScopes,
            request.AuthorizeRequest.CodeChallenge,
            request.AuthorizeRequest.CodeChallengeMethod,
            request.AuthorizeRequest.Nonce,
            request.AuthorizeRequest.State,
            request.AuthorizeRequest.Issuer,
            issuedAt);
        var authorizationCode = await AuthorizationCodeService.CreateAsync(requestContext, codeRequest, cancellationToken);
        string? idToken = null;
        if (request.AuthorizeRequest.AuthorizationFlow == DefaultAuthorizationFlows.Hybrid
            && request.GrantedResources.HasOpenId)
        {
            var idTokenRequest = new CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                request.Ticket.UserAuthentication,
                request.AuthorizeRequest.Client,
                request.GrantedResources,
                request.AuthorizeRequest.Nonce,
                request.AuthorizeRequest.State,
                request.AuthorizeRequest.Issuer,
                issuedAt,
                null,
                authorizationCode,
                request.AuthorizeRequest.Client.ShouldAlwaysIncludeUserClaimsInIdToken());
            var idTokenResult = await IdTokenService.CreateIdTokenAsync(requestContext, idTokenRequest, cancellationToken);
            if (idTokenResult.HasError)
            {
                return new(idTokenResult.ErrorDescription);
            }

            idToken = idTokenResult.IdToken.Handle;
        }

        var result = new SuccessfulAuthorizeResponse(authorizationCode, request.AuthorizeRequest.State, request.AuthorizeRequest.Issuer, idToken);
        return new(result);
    }
}
