using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Endpoints.Results.Implementations;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.ErrorService;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultAuthorizeEndpointCallbackHandler<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent, TAuthorizeRequestParameters>
    : IAuthorizeEndpointCallbackHandler
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRequestConsent : AbstractAuthorizeRequestConsent
    where TAuthorizeRequestParameters : AbstractAuthorizeRequestParameters
{
    public DefaultAuthorizeEndpointCallbackHandler(
        OpenIdentityFrameworkOptions frameworkOptions,
        ISystemClock systemClock,
        IIssuerUrlProvider issuerUrlProvider,
        IAuthorizeRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret> requestValidator,
        HtmlEncoder htmlEncoder,
        IErrorService errorService,
        IUserAuthenticationTicketService userAuthentication,
        IAuthorizeRequestConsentService<TRequestConsent> requestConsent,
        IAuthorizeRequestInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent> interactionService,
        IAuthorizeRequestParametersService<TAuthorizeRequestParameters> authorizeRequestParameters,
        IAuthorizeResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret> responseGenerator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(issuerUrlProvider);
        ArgumentNullException.ThrowIfNull(requestValidator);
        ArgumentNullException.ThrowIfNull(htmlEncoder);
        ArgumentNullException.ThrowIfNull(errorService);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        ArgumentNullException.ThrowIfNull(requestConsent);
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
        RequestConsent = requestConsent;
        InteractionService = interactionService;
        AuthorizeRequestParameters = authorizeRequestParameters;
        ResponseGenerator = responseGenerator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected ISystemClock SystemClock { get; }
    protected IIssuerUrlProvider IssuerUrlProvider { get; }
    protected IAuthorizeRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret> RequestValidator { get; }
    protected HtmlEncoder HtmlEncoder { get; }
    protected IErrorService ErrorService { get; }
    protected IUserAuthenticationTicketService UserAuthentication { get; }
    protected IAuthorizeRequestConsentService<TRequestConsent> RequestConsent { get; }
    protected IAuthorizeRequestInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent> InteractionService { get; }
    protected IAuthorizeRequestParametersService<TAuthorizeRequestParameters> AuthorizeRequestParameters { get; }
    protected IAuthorizeResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret> ResponseGenerator { get; }

    public virtual async Task<IEndpointHandlerResult> HandleAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        var issuer = await IssuerUrlProvider.GetIssuerAsync(httpContext, cancellationToken);
        IQueryCollection queryParameters;
        if (HttpMethods.IsGet(httpContext.Request.Method))
        {
            queryParameters = httpContext.Request.Query;
        }
        else
        {
            return new DefaultStatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var parametersReadResult = await ReadParametersAsync(httpContext, queryParameters, cancellationToken);
        if (parametersReadResult.HasError)
        {
            return await HandleErrorWithoutRedirectAsync(httpContext, parametersReadResult.ProtocolError, issuer, cancellationToken);
        }

        var validationResult = await RequestValidator.ValidateAsync(
            httpContext,
            parametersReadResult.AuthorizeRequestParameters.GetAuthorizeRequestParameters(),
            parametersReadResult.AuthorizeRequestParameters.GetInitialRequestDate(),
            issuer,
            cancellationToken);
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

        var userConsent = authenticationResult.IsAuthenticated
            ? await RequestConsent.ReadAsync(httpContext, parametersReadResult.AuthorizeRequestId, cancellationToken)
            : null;
        var interactionResult = await InteractionService.ProcessInteractionRequirementsAsync(
            httpContext,
            validationResult.ValidRequest,
            authenticationResult.Ticket,
            userConsent,
            cancellationToken);
        if (interactionResult.HasError)
        {
            return await HandlerErrorAsync(httpContext, interactionResult.ProtocolError, validationResult.ValidRequest, cancellationToken);
        }

        if (interactionResult.HasRequiredInteraction)
        {
            return await HandleRequiredInteraction(httpContext, interactionResult.RequiredInteraction, validationResult.ValidRequest, cancellationToken);
        }

        if (!interactionResult.HasValidRequest)
        {
            return await HandlerErrorAsync(httpContext, new(Errors.ServerError, "Incorrect interaction state"), validationResult.ValidRequest, cancellationToken);
        }

        var response = await ResponseGenerator.CreateResponseAsync(httpContext, interactionResult.ValidRequest, cancellationToken);
        await AuthorizeRequestParameters.DeleteAsync(httpContext, parametersReadResult.AuthorizeRequestId, cancellationToken);
        await RequestConsent.DeleteAsync(httpContext, parametersReadResult.AuthorizeRequestId, cancellationToken);
        var successfulResponseParameters = BuildSuccessfulResponseParameters(response);
        return new DefaultDirectAuthorizeResult(
            FrameworkOptions,
            HtmlEncoder,
            successfulResponseParameters,
            interactionResult.ValidRequest.AuthorizeRequest.ActualRedirectUri,
            interactionResult.ValidRequest.AuthorizeRequest.ResponseMode);
    }

    protected virtual async Task<ReadAuthorizeRequestParametersResult> ReadParametersAsync(HttpContext httpContext, IQueryCollection queryParameters, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(queryParameters);
        cancellationToken.ThrowIfCancellationRequested();
        string authorizeRequestId;
        if (queryParameters.TryGetValue(FrameworkOptions.UserInteraction.AuthorizeRequestIdParameterName, out var possibleAuthorizeRequestId)
            && possibleAuthorizeRequestId.Count == 1
            && !string.IsNullOrWhiteSpace(authorizeRequestId = possibleAuthorizeRequestId.ToString()))
        {
            var authorizeRequestParameters = await AuthorizeRequestParameters.ReadAsync(httpContext, authorizeRequestId, cancellationToken);
            if (authorizeRequestParameters != null)
            {
                return new(authorizeRequestId, authorizeRequestParameters);
            }
        }

        return new(new(Errors.InvalidRequest, "Authorize request not found"));
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

    protected virtual async Task<IEndpointHandlerResult> HandleRequiredInteraction(
        HttpContext httpContext,
        string requiredInteraction,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        if (requiredInteraction == DefaultInteractionResult.Login)
        {
            var authorizeRequestId = await AuthorizeRequestParameters.SaveAsync(httpContext, authorizeRequest.InitialRequestDate, authorizeRequest.Raw, cancellationToken);
            return new DefaultLoginUserPageResult(FrameworkOptions, authorizeRequestId);
        }

        if (requiredInteraction == DefaultInteractionResult.Consent)
        {
            var authorizeRequestId = await AuthorizeRequestParameters.SaveAsync(httpContext, authorizeRequest.InitialRequestDate, authorizeRequest.Raw, cancellationToken);
            return new DefaultConsentPageResult(FrameworkOptions, authorizeRequestId);
        }

        return await HandlerErrorAsync(httpContext, new(Errors.ServerError, "Incorrect interaction state"), authorizeRequest, cancellationToken);
    }

    protected virtual async Task<IEndpointHandlerResult> HandleErrorWithoutRedirectAsync(
        HttpContext httpContext,
        ProtocolError protocolError,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        cancellationToken.ThrowIfCancellationRequested();
        var errorToSave = new Error(protocolError, null, null, null, issuer);
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
                authorizeRequest.ActualRedirectUri,
                authorizeRequest.ResponseMode);
        }

        var errorToSave = new Error(protocolError, authorizeRequest.Client.GetClientId(), authorizeRequest.ActualRedirectUri, authorizeRequest.ResponseMode, authorizeRequest.Issuer);
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

    protected virtual IEnumerable<KeyValuePair<string, string?>> BuildSuccessfulResponseParameters(AuthorizeResponse authorizeResponse)
    {
        ArgumentNullException.ThrowIfNull(authorizeResponse);
        yield return new(ResponseParameters.Code, authorizeResponse.Code);
        if (authorizeResponse.State != null)
        {
            yield return new(ResponseParameters.State, authorizeResponse.State);
        }

        if (authorizeResponse.IdToken != null)
        {
            yield return new(ResponseParameters.IdToken, authorizeResponse.IdToken);
        }

        yield return new(ResponseParameters.Issuer, authorizeResponse.Issuer);
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

    protected class ReadAuthorizeRequestParametersResult
    {
        public ReadAuthorizeRequestParametersResult(ProtocolError protocolError)
        {
            ArgumentNullException.ThrowIfNull(protocolError);
            ProtocolError = protocolError;
            HasError = true;
        }

        public ReadAuthorizeRequestParametersResult(string authorizeRequestId, TAuthorizeRequestParameters authorizeRequestParameters)
        {
            ArgumentNullException.ThrowIfNull(authorizeRequestId);
            ArgumentNullException.ThrowIfNull(authorizeRequestParameters);
            AuthorizeRequestParameters = authorizeRequestParameters;
            AuthorizeRequestId = authorizeRequestId;
        }

        public string? AuthorizeRequestId { get; }

        public TAuthorizeRequestParameters? AuthorizeRequestParameters { get; }

        public ProtocolError? ProtocolError { get; }

        [MemberNotNullWhen(true, nameof(ProtocolError))]
        [MemberNotNullWhen(false, nameof(AuthorizeRequestParameters))]
        [MemberNotNullWhen(false, nameof(AuthorizeRequestId))]
        public bool HasError { get; }
    }
}
