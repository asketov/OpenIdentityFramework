using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Endpoints.Results.Implementations;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Token;
using OpenIdentityFramework.Services.Endpoints.Token.Validation;

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultTokenEndpointHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizationCode, TRefreshToken>
    : ITokenEndpointHandler<TRequestContext>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
{
    public DefaultTokenEndpointHandler(
        OpenIdentityFrameworkOptions frameworkOptions,
        IClientAuthenticationService<TRequestContext, TClient, TClientSecret> clientAuthentication,
        IIssuerUrlProvider<TRequestContext> issuerUrlProvider,
        ITokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> requestValidator,
        ITokenResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> responseGenerator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(clientAuthentication);
        ArgumentNullException.ThrowIfNull(issuerUrlProvider);
        ArgumentNullException.ThrowIfNull(requestValidator);
        ArgumentNullException.ThrowIfNull(responseGenerator);
        FrameworkOptions = frameworkOptions;
        ClientAuthentication = clientAuthentication;
        IssuerUrlProvider = issuerUrlProvider;
        RequestValidator = requestValidator;
        ResponseGenerator = responseGenerator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IClientAuthenticationService<TRequestContext, TClient, TClientSecret> ClientAuthentication { get; }
    protected IIssuerUrlProvider<TRequestContext> IssuerUrlProvider { get; }
    protected ITokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> RequestValidator { get; }
    protected ITokenResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> ResponseGenerator { get; }

    public virtual async Task<IEndpointHandlerResult> HandleAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-3.2
        // The client MUST use the HTTP POST method when making access token requests.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3
        // To obtain an Access Token, an ID Token, and optionally a Refresh Token,
        // the RP (Client) sends a Token Request to the Token Endpoint to obtain a Token Response,
        // as described in Section 3.2 of OAuth 2.0 [RFC6749], when using the Authorization Code Flow.
        if (!HttpMethods.IsPost(requestContext.HttpContext.Request.Method))
        {
            return new DefaultStatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        if (!requestContext.HttpContext.Request.HasApplicationFormContentType())
        {
            return new DefaultStatusCodeResult(HttpStatusCode.UnsupportedMediaType);
        }

        var form = await requestContext.HttpContext.Request.ReadFormAsync(cancellationToken);
        var clientAuthentication = await ClientAuthentication.AuthenticateAsync(requestContext, form, cancellationToken);
        var issuer = await IssuerUrlProvider.GetIssuerAsync(requestContext, cancellationToken);
        if (clientAuthentication.HasError)
        {
            return new DefaultTokenErrorResult(
                FrameworkOptions,
                new(TokenErrors.InvalidRequest, FrameworkOptions.ErrorHandling.HideErrorDescriptionsOnSafeAuthorizeErrorResponses ? null : clientAuthentication.ErrorDescription),
                issuer);
        }

        if (!clientAuthentication.IsAuthenticated)
        {
            return new DefaultTokenErrorResult(
                FrameworkOptions,
                new(TokenErrors.InvalidClient, null),
                issuer);
        }

        var validationResult = await RequestValidator.ValidateAsync(requestContext, form, clientAuthentication.Client, clientAuthentication.ClientAuthenticationMethod, issuer, cancellationToken);
        if (validationResult.HasError)
        {
            return new DefaultTokenErrorResult(
                FrameworkOptions,
                validationResult.ProtocolError,
                issuer);
        }

        var responseGenerationResult = await ResponseGenerator.CreateResponseAsync(requestContext, validationResult.ValidRequest, cancellationToken);
        if (responseGenerationResult.HasError)
        {
            return new DefaultTokenErrorResult(
                FrameworkOptions,
                new(TokenErrors.InvalidGrant, responseGenerationResult.ErrorDescription),
                issuer);
        }

        return new DefaultTokenSuccessfulResult(FrameworkOptions, responseGenerationResult.TokenResponse);
    }
}
