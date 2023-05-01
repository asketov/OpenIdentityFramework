using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Endpoints.Results.Implementations;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.ErrorService;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultAuthorizeEndpointHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent, TAuthorizeRequestParameters>
    : IAuthorizeEndpointHandler<TRequestContext>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRequestConsent : AbstractAuthorizeRequestConsent
    where TAuthorizeRequestParameters : AbstractAuthorizeRequestParameters
{
    public DefaultAuthorizeEndpointHandler(
        OpenIdentityFrameworkOptions frameworkOptions,
        ISystemClock systemClock,
        IIssuerUrlProvider<TRequestContext> issuerUrlProvider,
        IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> requestValidator,
        HtmlEncoder htmlEncoder,
        IErrorService<TRequestContext> errorService,
        IUserAuthenticationTicketService<TRequestContext> userAuthentication,
        IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent> interactionService,
        IAuthorizeRequestParametersService<TRequestContext, TAuthorizeRequestParameters> authorizeRequestParameters,
        IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> responseGenerator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(issuerUrlProvider);
        ArgumentNullException.ThrowIfNull(requestValidator);
        ArgumentNullException.ThrowIfNull(htmlEncoder);
        ArgumentNullException.ThrowIfNull(errorService);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        ArgumentNullException.ThrowIfNull(interactionService);
        ArgumentNullException.ThrowIfNull(authorizeRequestParameters);
        ArgumentNullException.ThrowIfNull(responseGenerator);
        FrameworkOptions = frameworkOptions;
        SystemClock = systemClock;
        IssuerUrlProvider = issuerUrlProvider;
        RequestValidator = requestValidator;
        HtmlEncoder = htmlEncoder;
        ErrorService = errorService;
        UserAuthentication = userAuthentication;
        InteractionService = interactionService;
        AuthorizeRequestParameters = authorizeRequestParameters;
        ResponseGenerator = responseGenerator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected ISystemClock SystemClock { get; }
    protected IIssuerUrlProvider<TRequestContext> IssuerUrlProvider { get; }
    protected IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> RequestValidator { get; }
    protected HtmlEncoder HtmlEncoder { get; }
    protected IErrorService<TRequestContext> ErrorService { get; }
    protected IUserAuthenticationTicketService<TRequestContext> UserAuthentication { get; }
    protected IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent> InteractionService { get; }
    protected IAuthorizeRequestParametersService<TRequestContext, TAuthorizeRequestParameters> AuthorizeRequestParameters { get; }
    protected IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ResponseGenerator { get; }

    public virtual async Task<IEndpointHandlerResult<TRequestContext>> HandleAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        var initialRequestDate = SystemClock.UtcNow;
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
                return new DefaultStatusCodeResult<TRequestContext>(HttpStatusCode.UnsupportedMediaType);
            }

            var form = await requestContext.HttpContext.Request.ReadFormAsync(cancellationToken);
            parameters = form.AsReadOnlyDictionary();
        }
        else
        {
            return new DefaultStatusCodeResult<TRequestContext>(HttpStatusCode.MethodNotAllowed);
        }

        var issuer = await IssuerUrlProvider.GetIssuerAsync(requestContext, cancellationToken);
        var validationResult = await RequestValidator.ValidateAsync(requestContext, parameters, initialRequestDate, issuer, cancellationToken);
        if (validationResult.HasError)
        {
            return await HandleValidationErrorAsync(requestContext, validationResult.ValidationError, cancellationToken);
        }

        var authenticationResult = await UserAuthentication.AuthenticateAsync(requestContext, cancellationToken);
        if (authenticationResult.HasError)
        {
            var authenticationError = new ProtocolError(Errors.ServerError, authenticationResult.ErrorDescription);
            return await HandlerErrorAsync(requestContext, authenticationError, validationResult.ValidRequest, cancellationToken);
        }

        var interactionResult = await InteractionService.ProcessInteractionRequirementsAsync(
            requestContext,
            validationResult.ValidRequest,
            authenticationResult.Ticket,
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
            return await HandlerErrorAsync(requestContext, new(Errors.ServerError, "Incorrect interaction state"), validationResult.ValidRequest, cancellationToken);
        }

        var responseResult = await ResponseGenerator.CreateResponseAsync(requestContext, interactionResult.ValidRequest, cancellationToken);
        if (responseResult.HasError)
        {
            return await HandlerErrorAsync(requestContext, new(Errors.ServerError, responseResult.ErrorDescription), validationResult.ValidRequest, cancellationToken);
        }

        var successfulResponseParameters = BuildSuccessfulResponseParameters(responseResult.AuthorizeResponse);
        return new DefaultDirectAuthorizeResult<TRequestContext>(
            FrameworkOptions,
            HtmlEncoder,
            successfulResponseParameters,
            interactionResult.ValidRequest.AuthorizeRequest.ActualRedirectUri,
            interactionResult.ValidRequest.AuthorizeRequest.ResponseMode);
    }


    protected virtual async Task<IEndpointHandlerResult<TRequestContext>> HandleValidationErrorAsync(
        TRequestContext requestContext,
        AuthorizeRequestValidationError<TClient, TClientSecret> validationError,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(validationError);
        cancellationToken.ThrowIfCancellationRequested();
        if (validationError.CanReturnErrorDirectly)
        {
            var errorParameters = BuildErrorResponseParameters(validationError.ProtocolError, validationError.State, validationError.Issuer);
            return new DefaultDirectAuthorizeResult<TRequestContext>(
                FrameworkOptions,
                HtmlEncoder,
                errorParameters,
                validationError.RedirectUri,
                validationError.ResponseMode);
        }

        var errorToSave = new Error(validationError.ProtocolError, validationError.Client?.GetClientId(), validationError.RedirectUri, validationError.ResponseMode, validationError.Issuer);
        var errorId = await ErrorService.SaveAsync(requestContext, errorToSave, cancellationToken);
        return new DefaultErrorPageResult<TRequestContext>(FrameworkOptions, errorId);
    }

    protected virtual async Task<IEndpointHandlerResult<TRequestContext>> HandleRequiredInteraction(
        TRequestContext requestContext,
        string requiredInteraction,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        if (requiredInteraction == DefaultInteractionResult.Login)
        {
            var authorizeRequestId = await AuthorizeRequestParameters.SaveAsync(requestContext, authorizeRequest.InitialRequestDate, authorizeRequest.Raw, cancellationToken);
            return new DefaultLoginUserPageResult<TRequestContext>(FrameworkOptions, authorizeRequestId);
        }

        if (requiredInteraction == DefaultInteractionResult.Consent)
        {
            var authorizeRequestId = await AuthorizeRequestParameters.SaveAsync(requestContext, authorizeRequest.InitialRequestDate, authorizeRequest.Raw, cancellationToken);
            return new DefaultConsentPageResult<TRequestContext>(FrameworkOptions, authorizeRequestId);
        }

        return await HandlerErrorAsync(requestContext, new(Errors.ServerError, "Incorrect interaction state"), authorizeRequest, cancellationToken);
    }

    protected virtual async Task<IEndpointHandlerResult<TRequestContext>> HandlerErrorAsync(
        TRequestContext requestContext,
        ProtocolError protocolError,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        if (IsSafeError(protocolError))
        {
            var errorParameters = BuildErrorResponseParameters(protocolError, authorizeRequest.State, authorizeRequest.Issuer);
            return new DefaultDirectAuthorizeResult<TRequestContext>(
                FrameworkOptions,
                HtmlEncoder,
                errorParameters,
                authorizeRequest.ActualRedirectUri,
                authorizeRequest.ResponseMode);
        }

        var errorToSave = new Error(protocolError, authorizeRequest.Client.GetClientId(), authorizeRequest.ActualRedirectUri, authorizeRequest.ResponseMode, authorizeRequest.Issuer);
        var errorId = await ErrorService.SaveAsync(requestContext, errorToSave, cancellationToken);
        return new DefaultErrorPageResult<TRequestContext>(FrameworkOptions, errorId);
    }

    protected virtual IEnumerable<KeyValuePair<string, string?>> BuildErrorResponseParameters(
        ProtocolError protocolError,
        string? state,
        string issuer)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        yield return new(ResponseParameters.Error, protocolError.Error);
        if (!FrameworkOptions.ErrorHandling.HideErrorDescriptionsOnSafeAuthorizeErrorResponses && !string.IsNullOrWhiteSpace(protocolError.Description))
        {
            yield return new(ResponseParameters.ErrorDescription, protocolError.Description);
        }

        if (state != null)
        {
            yield return new(ResponseParameters.State, state);
        }

        yield return new(ResponseParameters.Issuer, issuer);
    }

    protected virtual IEnumerable<KeyValuePair<string, string?>> BuildSuccessfulResponseParameters(SuccessfulAuthorizeResponse successfulAuthorizeResponse)
    {
        ArgumentNullException.ThrowIfNull(successfulAuthorizeResponse);
        yield return new(ResponseParameters.Code, successfulAuthorizeResponse.Code);
        if (successfulAuthorizeResponse.State != null)
        {
            yield return new(ResponseParameters.State, successfulAuthorizeResponse.State);
        }

        if (successfulAuthorizeResponse.IdToken != null)
        {
            yield return new(ResponseParameters.IdToken, successfulAuthorizeResponse.IdToken);
        }

        yield return new(ResponseParameters.Issuer, successfulAuthorizeResponse.Issuer);
    }

    protected virtual bool IsSafeError(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        return protocolError.Error == Errors.AccessDenied
               || protocolError.Error == Errors.TemporarilyUnavailable
               || protocolError.Error == Errors.InteractionRequired
               || protocolError.Error == Errors.LoginRequired
               || protocolError.Error == Errors.AccountSelectionRequired
               || protocolError.Error == Errors.ConsentRequired;
    }
}
