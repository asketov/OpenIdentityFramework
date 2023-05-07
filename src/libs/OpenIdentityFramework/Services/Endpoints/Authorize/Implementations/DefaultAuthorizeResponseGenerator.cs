using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
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
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var authorizationCodeIssuedAt = SystemClock.UtcNow;
        var authorizationCodeResult = await AuthorizationCodeService.CreateAsync(
            requestContext,
            request.AuthorizeRequest.Client,
            request.ResourceOwnerProfile.EssentialClaims,
            request.GrantedResources.RawScopes,
            request.AuthorizeRequest.AuthorizeRequestRedirectUri,
            request.AuthorizeRequest.CodeChallenge,
            request.AuthorizeRequest.CodeChallengeMethod,
            authorizationCodeIssuedAt,
            cancellationToken);
        string? idToken = null;
        if (request.AuthorizeRequest.AuthorizationFlow == DefaultAuthorizationFlows.Hybrid)
        {
            if (string.IsNullOrEmpty(request.AuthorizeRequest.Nonce))
            {
                return new("Nonce is required for hybrid flow");
            }

            var idTokenIssuedAt = authorizationCodeResult.IssuedAt;
            var idTokenResult = await IdTokenService.CreateIdTokenAsync(
                requestContext,
                request.AuthorizeRequest.Client,
                request.AuthorizeRequest.Issuer,
                authorizationCodeResult.Handle,
                null,
                request.AuthorizeRequest.Nonce,
                request.ResourceOwnerProfile,
                request.GrantedResources,
                idTokenIssuedAt,
                cancellationToken);
            if (idTokenResult.HasError)
            {
                return new(idTokenResult.ErrorDescription);
            }

            idToken = idTokenResult.IdToken.Handle;
        }

        var result = new SuccessfulAuthorizeResponse(authorizationCodeResult.Handle, request.AuthorizeRequest.State, request.AuthorizeRequest.Issuer, idToken);
        return new(result);
    }
}
