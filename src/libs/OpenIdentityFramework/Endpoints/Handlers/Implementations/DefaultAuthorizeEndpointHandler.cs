﻿using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Responses.Authorize;
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

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultAuthorizeEndpointHandler<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent> : IAuthorizeEndpointHandler
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRequestConsent : AbstractAuthorizeRequestConsent

{
    public DefaultAuthorizeEndpointHandler(
        OpenIdentityFrameworkOptions frameworkOptions,
        ISystemClock systemClock,
        IIssuerUrlProvider issuerUrlProvider,
        IAuthorizeRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret> requestValidator,
        HtmlEncoder htmlEncoder,
        IErrorService errorService,
        IUserAuthenticationService userAuthentication,
        IAuthorizeRequestInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent> interactionService)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(issuerUrlProvider);
        ArgumentNullException.ThrowIfNull(requestValidator);
        ArgumentNullException.ThrowIfNull(htmlEncoder);
        ArgumentNullException.ThrowIfNull(errorService);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        ArgumentNullException.ThrowIfNull(interactionService);
        FrameworkOptions = frameworkOptions;
        SystemClock = systemClock;
        IssuerUrlProvider = issuerUrlProvider;
        RequestValidator = requestValidator;
        HtmlEncoder = htmlEncoder;
        ErrorService = errorService;
        UserAuthentication = userAuthentication;
        InteractionService = interactionService;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected ISystemClock SystemClock { get; }
    protected IIssuerUrlProvider IssuerUrlProvider { get; }
    protected IAuthorizeRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret> RequestValidator { get; }
    protected HtmlEncoder HtmlEncoder { get; }
    protected IErrorService ErrorService { get; }
    protected IUserAuthenticationService UserAuthentication { get; }
    protected IAuthorizeRequestInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent> InteractionService { get; }

    public virtual async Task<IEndpointHandlerResult> HandleAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
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
        if (HttpMethods.IsGet(httpContext.Request.Method))
        {
            parameters = httpContext.Request.Query.AsReadOnlyDictionary();
        }
        else if (HttpMethods.IsPost(httpContext.Request.Method))
        {
            if (!httpContext.Request.HasApplicationFormContentType())
            {
                return new DefaultStatusCodeResult(HttpStatusCode.UnsupportedMediaType);
            }

            var form = await httpContext.Request.ReadFormAsync(cancellationToken);
            parameters = form.AsReadOnlyDictionary();
        }
        else
        {
            return new DefaultStatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var issuer = await IssuerUrlProvider.GetIssuerAsync(httpContext, cancellationToken);
        var validationResult = await RequestValidator.ValidateAsync(httpContext, parameters, initialRequestDate, issuer, cancellationToken);
        if (validationResult.HasError)
        {
            return await HandleValidationErrorAsync(httpContext, validationResult.ValidationError, cancellationToken);
        }

        var authenticationResult = await UserAuthentication.AuthenticateAsync(httpContext, cancellationToken);
        if (authenticationResult.HasError)
        {
            var authenticationError = new ProtocolError(Errors.ServerError, authenticationResult.ErrorDescription);
            return await HandlerErrorAsync(httpContext, authenticationError, validationResult.ValidRequest, cancellationToken);
        }

        var interactionResult = await InteractionService.ProcessInteractionRequirementsAsync(
            httpContext,
            validationResult.ValidRequest,
            authenticationResult.UserAuthentication,
            null,
            cancellationToken);
        if (interactionResult.HasError)
        {
            return await HandlerErrorAsync(httpContext, interactionResult.ProtocolError, validationResult.ValidRequest, cancellationToken);
        }

        if (interactionResult.HasRequiredInteraction)
        {
            // todo: handle interaction
        }

        if (!interactionResult.HasValidRequest)
        {
            return await HandlerErrorAsync(httpContext, new(Errors.ServerError, "Incorrect interaction state"), validationResult.ValidRequest, cancellationToken);
        }

        // todo: create code and return result
        throw new NotImplementedException();
    }

    protected virtual async Task<IEndpointHandlerResult> HandleValidationErrorAsync(
        HttpContext httpContext,
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

        var errorToSave = new Error(validationError.ProtocolError, validationError.Client?.GetClientId(), validationError.RedirectUri, validationError.ResponseMode, validationError.Issuer);
        var errorId = await ErrorService.SaveAsync(httpContext, errorToSave, cancellationToken);
        return new DefaultErrorPageResult(FrameworkOptions, errorId);
    }

    protected virtual async Task<IEndpointHandlerResult> HandlerErrorAsync(
        HttpContext httpContext,
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
                authorizeRequest.RedirectUri,
                authorizeRequest.ResponseMode);
        }

        var errorToSave = new Error(protocolError, authorizeRequest.Client.GetClientId(), authorizeRequest.RedirectUri, authorizeRequest.ResponseMode, authorizeRequest.Issuer);
        var errorId = await ErrorService.SaveAsync(httpContext, errorToSave, cancellationToken);
        return new DefaultErrorPageResult(FrameworkOptions, errorId);
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
