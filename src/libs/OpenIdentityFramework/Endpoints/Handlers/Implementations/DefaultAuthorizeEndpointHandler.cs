using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Endpoints.Results.Implementations;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultAuthorizeEndpointHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestError, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizeRequest, TAuthorizeRequestConsent>
    : IAuthorizeEndpointHandler<TRequestContext>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TAuthorizeRequestError : AbstractAuthorizeRequestError
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
    where TAuthorizeRequest : AbstractAuthorizeRequest
    where TAuthorizeRequestConsent : AbstractAuthorizeRequestConsent<TResourceOwnerIdentifiers>
{
    public DefaultAuthorizeEndpointHandler(
        OpenIdentityFrameworkOptions frameworkOptions,
        TimeProvider timeProvider,
        IIssuerUrlProvider<TRequestContext> issuerUrlProvider,
        IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> requestValidator,
        HtmlEncoder htmlEncoder,
        IAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError> errorService,
        IResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> resourceOwnerAuthentication,
        IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestConsent, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> interactionService,
        IAuthorizeRequestService<TRequestContext, TAuthorizeRequest> authorizeRequest,
        IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> responseGenerator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(issuerUrlProvider);
        ArgumentNullException.ThrowIfNull(requestValidator);
        ArgumentNullException.ThrowIfNull(htmlEncoder);
        ArgumentNullException.ThrowIfNull(errorService);
        ArgumentNullException.ThrowIfNull(resourceOwnerAuthentication);
        ArgumentNullException.ThrowIfNull(interactionService);
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(responseGenerator);
        FrameworkOptions = frameworkOptions;
        TimeProvider = timeProvider;
        IssuerUrlProvider = issuerUrlProvider;
        RequestValidator = requestValidator;
        HtmlEncoder = htmlEncoder;
        ErrorService = errorService;
        ResourceOwnerAuthentication = resourceOwnerAuthentication;
        InteractionService = interactionService;
        AuthorizeRequest = authorizeRequest;
        ResponseGenerator = responseGenerator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected TimeProvider TimeProvider { get; }
    protected IIssuerUrlProvider<TRequestContext> IssuerUrlProvider { get; }
    protected IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> RequestValidator { get; }
    protected HtmlEncoder HtmlEncoder { get; }
    protected IAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError> ErrorService { get; }
    protected IResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> ResourceOwnerAuthentication { get; }
    protected IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestConsent, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> InteractionService { get; }
    protected IAuthorizeRequestService<TRequestContext, TAuthorizeRequest> AuthorizeRequest { get; }
    protected IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> ResponseGenerator { get; }


    public virtual async Task<IEndpointHandlerResult> HandleAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        var initialRequestDate = TimeProvider.GetUtcNow();
        IReadOnlyDictionary<string, StringValues> parameters;
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // The authorization server MUST support the use of the HTTP GET method Section 9.3.1 of [RFC9110] for the authorization endpoint
        // and MAY support the POST method (Section 9.3.3 of RFC9110) as well.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // Authorization Servers MUST support the use of the HTTP GET and POST methods defined in RFC 2616 [RFC2616] at the Authorization Endpoint.
        // Clients MAY use the HTTP GET or POST methods to send the Authorization Request to the Authorization Server.
        // If using the HTTP GET method, the request parameters are serialized using URI Query String Serialization, per Section 13.1.
        // If using the HTTP POST method, the request parameters are serialized using Form Serialization, per Section 13.2.
        if (HttpMethods.IsGet(requestContext.HttpContext.Request.Method))
        {
            parameters = requestContext.HttpContext.Request.Query.AsReadOnlyDictionary();
        }
        else if (HttpMethods.IsPost(requestContext.HttpContext.Request.Method))
        {
            if (!requestContext.HttpContext.Request.HasApplicationFormContentType())
            {
                return new DefaultStatusCodeResult(HttpStatusCode.UnsupportedMediaType);
            }

            var form = await requestContext.HttpContext.Request.ReadFormAsync(cancellationToken);
            parameters = form.AsReadOnlyDictionary();
        }
        else
        {
            return new DefaultStatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var issuer = await IssuerUrlProvider.GetIssuerAsync(requestContext, cancellationToken);
        var validationResult = await RequestValidator.ValidateAsync(requestContext, parameters, initialRequestDate, issuer, cancellationToken);
        if (validationResult.HasError)
        {
            return await HandleValidationErrorAsync(requestContext, validationResult.ValidationError, cancellationToken);
        }

        var authenticationResult = await ResourceOwnerAuthentication.AuthenticateAsync(requestContext, cancellationToken);
        if (authenticationResult.HasError)
        {
            var authenticationError = new ProtocolError(AuthorizeErrors.ServerError, authenticationResult.ErrorDescription);
            return await HandlerErrorAsync(requestContext, authenticationError, validationResult.ValidRequest, cancellationToken);
        }

        var interactionResult = await InteractionService.ProcessInteractionRequirementsAsync(
            requestContext,
            validationResult.ValidRequest,
            authenticationResult.Authentication,
            null,
            cancellationToken);
        if (interactionResult.HasError)
        {
            return await HandlerErrorAsync(requestContext, interactionResult.ProtocolError, validationResult.ValidRequest, cancellationToken);
        }

        if (interactionResult.HasRequiredInteraction)
        {
            return await HandleRequiredInteraction(requestContext, interactionResult.RequiredInteraction, validationResult.ValidRequest, cancellationToken);
        }

        if (!interactionResult.HasValidRequest)
        {
            return await HandlerErrorAsync(requestContext, new(AuthorizeErrors.ServerError, "Incorrect interaction state"), validationResult.ValidRequest, cancellationToken);
        }

        var responseResult = await ResponseGenerator.CreateResponseAsync(requestContext, interactionResult.ValidRequest, cancellationToken);
        if (responseResult.HasError)
        {
            return await HandlerErrorAsync(requestContext, new(AuthorizeErrors.ServerError, responseResult.ErrorDescription), validationResult.ValidRequest, cancellationToken);
        }

        var successfulResponseParameters = BuildSuccessfulResponseParameters(responseResult.AuthorizeResponse);
        return new DefaultDirectAuthorizeResult(
            FrameworkOptions,
            HtmlEncoder,
            successfulResponseParameters,
            interactionResult.ValidRequest.AuthorizeRequest.RedirectUriToUse,
            interactionResult.ValidRequest.AuthorizeRequest.ResponseMode);
    }


    protected virtual async Task<IEndpointHandlerResult> HandleValidationErrorAsync(
        TRequestContext requestContext,
        AuthorizeRequestValidationError<TClient, TClientSecret> validationError,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(validationError);
        cancellationToken.ThrowIfCancellationRequested();
        if (validationError.CanReturnErrorDirectly)
        {
            var errorParameters = BuildErrorResponseParameters(validationError.ProtocolError, validationError.State, validationError.Issuer);
            return new DefaultDirectAuthorizeResult(
                FrameworkOptions,
                HtmlEncoder,
                errorParameters,
                validationError.RedirectUri,
                validationError.ResponseMode);
        }

        var errorId = await ErrorService.CreateAsync(
            requestContext,
            validationError.ProtocolError,
            validationError.Client?.GetClientId(),
            validationError.RedirectUri,
            validationError.ResponseMode,
            validationError.State,
            validationError.Issuer,
            cancellationToken);
        return new DefaultErrorPageResult(FrameworkOptions, errorId);
    }

    protected virtual async Task<IEndpointHandlerResult> HandleRequiredInteraction(
        TRequestContext requestContext,
        string requiredInteraction,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        if (requiredInteraction == DefaultInteractionResult.Login)
        {
            var authorizeRequestId = await AuthorizeRequest.SaveAsync(requestContext, authorizeRequest.InitialRequestDate, authorizeRequest.Raw, cancellationToken);
            return new DefaultLoginUserPageResult(FrameworkOptions, authorizeRequestId);
        }

        if (requiredInteraction == DefaultInteractionResult.Consent)
        {
            var authorizeRequestId = await AuthorizeRequest.SaveAsync(requestContext, authorizeRequest.InitialRequestDate, authorizeRequest.Raw, cancellationToken);
            return new DefaultConsentPageResult(FrameworkOptions, authorizeRequestId);
        }

        return await HandlerErrorAsync(requestContext, new(AuthorizeErrors.ServerError, "Incorrect interaction state"), authorizeRequest, cancellationToken);
    }

    protected virtual async Task<IEndpointHandlerResult> HandlerErrorAsync(
        TRequestContext requestContext,
        ProtocolError protocolError,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        if (IsSafeError(protocolError))
        {
            var errorParameters = BuildErrorResponseParameters(protocolError, authorizeRequest.State, authorizeRequest.Issuer);
            return new DefaultDirectAuthorizeResult(
                FrameworkOptions,
                HtmlEncoder,
                errorParameters,
                authorizeRequest.RedirectUriToUse,
                authorizeRequest.ResponseMode);
        }

        var errorId = await ErrorService.CreateAsync(
            requestContext,
            protocolError,
            authorizeRequest.Client.GetClientId(),
            authorizeRequest.RedirectUriToUse,
            authorizeRequest.ResponseMode,
            authorizeRequest.State,
            authorizeRequest.Issuer,
            cancellationToken);
        return new DefaultErrorPageResult(FrameworkOptions, errorId);
    }

    protected virtual IEnumerable<KeyValuePair<string, string?>> BuildErrorResponseParameters(
        ProtocolError protocolError,
        string? state,
        string issuer)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        yield return new(AuthorizeResponseParameters.Error, protocolError.Error);
        if (!FrameworkOptions.ErrorHandling.HideErrorDescriptionsOnSafeAuthorizeErrorResponses && !string.IsNullOrWhiteSpace(protocolError.Description))
        {
            yield return new(AuthorizeResponseParameters.ErrorDescription, protocolError.Description);
        }

        if (state != null)
        {
            yield return new(AuthorizeResponseParameters.State, state);
        }

        yield return new(AuthorizeResponseParameters.Issuer, issuer);
    }

    protected virtual IEnumerable<KeyValuePair<string, string?>> BuildSuccessfulResponseParameters(SuccessfulAuthorizeResponse successfulAuthorizeResponse)
    {
        ArgumentNullException.ThrowIfNull(successfulAuthorizeResponse);
        yield return new(AuthorizeResponseParameters.Code, successfulAuthorizeResponse.Code);
        if (successfulAuthorizeResponse.State != null)
        {
            yield return new(AuthorizeResponseParameters.State, successfulAuthorizeResponse.State);
        }

        if (successfulAuthorizeResponse.IdToken != null)
        {
            yield return new(AuthorizeResponseParameters.IdToken, successfulAuthorizeResponse.IdToken);
        }

        yield return new(AuthorizeResponseParameters.Issuer, successfulAuthorizeResponse.Issuer);
    }

    protected virtual bool IsSafeError(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        return protocolError.Error == AuthorizeErrors.AccessDenied
               || protocolError.Error == AuthorizeErrors.TemporarilyUnavailable
               || protocolError.Error == AuthorizeErrors.InteractionRequired
               || protocolError.Error == AuthorizeErrors.LoginRequired
               || protocolError.Error == AuthorizeErrors.AccountSelectionRequired
               || protocolError.Error == AuthorizeErrors.ConsentRequired;
    }
}
