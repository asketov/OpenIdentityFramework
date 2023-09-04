using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizationCode>
    : IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
{
    public DefaultAuthorizeResponseGenerator(
        TimeProvider timeProvider,
        IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> authorizationCodeService,
        IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> idTokenService)
    {
        TimeProvider = timeProvider;
        AuthorizationCodeService = authorizationCodeService;
        IdTokenService = idTokenService;
    }

    protected TimeProvider TimeProvider { get; }
    protected IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> AuthorizationCodeService { get; }
    protected IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> IdTokenService { get; }

    public virtual async Task<AuthorizeResponseGenerationResult> CreateResponseAsync(
        TRequestContext requestContext,
        ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var authorizationCodeIssuedAt = TimeProvider.GetUtcNow();
        var authorizationCodeResult = await AuthorizationCodeService.CreateAsync(
            requestContext,
            request.AuthorizeRequest.Client,
            request.ResourceOwnerProfile.EssentialClaims,
            request.GrantedResources.RawScopes,
            request.AuthorizeRequest.CodeChallenge,
            request.AuthorizeRequest.CodeChallengeMethod,
            authorizationCodeIssuedAt,
            cancellationToken);
        string? idToken = null;
        if (request.AuthorizeRequest.ResponseType.SetEquals(DefaultResponseTypes.CodeIdToken))
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
                request.AuthorizeRequest.Client.ShouldIncludeUserClaimsInIdTokenAuthorizeResponse(),
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
