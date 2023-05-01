using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Response.Token;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Endpoints.Results.Implementations;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Token;

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultTokenEndpointHandler<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    : ITokenEndpointHandler
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public DefaultTokenEndpointHandler(
        OpenIdentityFrameworkOptions frameworkOptions,
        IClientAuthenticationService<TClient, TClientSecret> clientAuthentication,
        IIssuerUrlProvider issuerUrlProvider,
        ITokenRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> requestValidator,
        ITokenResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> responseGenerator)
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
    protected IClientAuthenticationService<TClient, TClientSecret> ClientAuthentication { get; }
    protected IIssuerUrlProvider IssuerUrlProvider { get; }
    protected ITokenRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> RequestValidator { get; }
    protected ITokenResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> ResponseGenerator { get; }

    public virtual async Task<IEndpointHandlerResult> HandleAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2
        // The client MUST use the HTTP POST method when making access token requests.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3
        // To obtain an Access Token, an ID Token, and optionally a Refresh Token,
        // the RP (Client) sends a Token Request to the Token Endpoint to obtain a Token Response,
        // as described in Section 3.2 of OAuth 2.0 [RFC6749], when using the Authorization Code Flow.
        if (!HttpMethods.IsPost(httpContext.Request.Method))
        {
            return new DefaultStatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        if (!httpContext.Request.HasApplicationFormContentType())
        {
            return new DefaultStatusCodeResult(HttpStatusCode.UnsupportedMediaType);
        }

        var form = await httpContext.Request.ReadFormAsync(cancellationToken);
        var authenticationResult = await ClientAuthentication.AuthenticateAsync(httpContext, form, cancellationToken);
        var issuer = await IssuerUrlProvider.GetIssuerAsync(httpContext, cancellationToken);
        if (authenticationResult.HasError)
        {
            return new DefaultTokenErrorResult(
                FrameworkOptions,
                new(Errors.InvalidRequest, FrameworkOptions.ErrorHandling.HideErrorDescriptionsOnSafeAuthorizeErrorResponses ? null : authenticationResult.ErrorDescription),
                issuer);
        }

        if (!authenticationResult.IsAuthenticated)
        {
            return new DefaultTokenErrorResult(
                FrameworkOptions,
                new(Errors.InvalidClient, null),
                issuer);
        }

        var validationResult = await RequestValidator.ValidateAsync(httpContext, form, authenticationResult.Client, issuer, cancellationToken);
        if (validationResult.HasError)
        {
            return new DefaultTokenErrorResult(
                FrameworkOptions,
                validationResult.ProtocolError,
                issuer);
        }

        var response = await ResponseGenerator.CreateResponseAsync(httpContext, validationResult.ValidRequest, cancellationToken);
        return new DefaultTokenSuccessfulResult(FrameworkOptions, response);
    }
}
