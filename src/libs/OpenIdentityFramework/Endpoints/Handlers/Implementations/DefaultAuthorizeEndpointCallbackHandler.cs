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
using OpenIdentityFramework.Constants.Response;
using OpenIdentityFramework.Constants.Response.Errors;
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

public class DefaultAuthorizeEndpointCallbackHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent, TAuthorizeRequestParameters>
    : IAuthorizeEndpointCallbackHandler<TRequestContext>
    where TRequestContext : AbstractRequestContext
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
        IIssuerUrlProvider<TRequestContext> issuerUrlProvider,
        IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> requestValidator,
        HtmlEncoder htmlEncoder,
        IErrorService<TRequestContext> errorService,
        IResourceOwnerAuthenticationService<TRequestContext> resourceOwnerAuthentication,
        IAuthorizeRequestConsentService<TRequestContext, TRequestConsent> requestConsent,
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
        ArgumentNullException.ThrowIfNull(resourceOwnerAuthentication);
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
        ResourceOwnerAuthentication = resourceOwnerAuthentication;
        RequestConsent = requestConsent;
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
    protected IResourceOwnerAuthenticationService<TRequestContext> ResourceOwnerAuthentication { get; }
    protected IAuthorizeRequestConsentService<TRequestContext, TRequestConsent> RequestConsent { get; }
    protected IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent> InteractionService { get; }
    protected IAuthorizeRequestParametersService<TRequestContext, TAuthorizeRequestParameters> AuthorizeRequestParameters { get; }
    protected IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ResponseGenerator { get; }

    public virtual async Task<IEndpointHandlerResult> HandleAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        var issuer = await IssuerUrlProvider.GetIssuerAsync(requestContext, cancellationToken);
        IQueryCollection queryParameters;
        if (HttpMethods.IsGet(requestContext.HttpContext.Request.Method))
        {
            queryParameters = requestContext.HttpContext.Request.Query;
        }
        else
        {
            return new DefaultStatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var parametersReadResult = await ReadParametersAsync(requestContext, queryParameters, cancellationToken);
        if (parametersReadResult.HasError)
        {
            return await HandleErrorWithoutRedirectAsync(requestContext, parametersReadResult.ProtocolError, issuer, cancellationToken);
        }

        var validationResult = await RequestValidator.ValidateAsync(
            requestContext,
            parametersReadResult.AuthorizeRequestParameters.GetAuthorizeRequestParameters(),
            parametersReadResult.AuthorizeRequestParameters.GetInitialRequestDate(),
            issuer,
            cancellationToken);
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

        var userConsent = authenticationResult.IsAuthenticated
            ? await RequestConsent.ReadAsync(
                requestContext,
                authenticationResult.Authentication.EssentialClaims.Identifiers,
                parametersReadResult.AuthorizeRequestId,
                cancellationToken)
            : null;
        var interactionResult = await InteractionService.ProcessInteractionRequirementsAsync(
            requestContext,
            validationResult.ValidRequest,
            authenticationResult.Authentication,
            userConsent,
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

        await AuthorizeRequestParameters.DeleteAsync(requestContext, parametersReadResult.AuthorizeRequestId, cancellationToken);
        await RequestConsent.DeleteAsync(requestContext, parametersReadResult.AuthorizeRequestId, cancellationToken);
        var successfulResponseParameters = BuildSuccessfulResponseParameters(responseResult.AuthorizeResponse);
        return new DefaultDirectAuthorizeResult(
            FrameworkOptions,
            HtmlEncoder,
            successfulResponseParameters,
            interactionResult.ValidRequest.AuthorizeRequest.RedirectUriToUse,
            interactionResult.ValidRequest.AuthorizeRequest.ResponseMode);
    }

    protected virtual async Task<ReadAuthorizeRequestParametersResult> ReadParametersAsync(
        TRequestContext requestContext,
        IQueryCollection queryParameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(queryParameters);
        cancellationToken.ThrowIfCancellationRequested();
        string authorizeRequestId;
        if (queryParameters.TryGetValue(FrameworkOptions.UserInteraction.AuthorizeRequestIdParameterName, out var possibleAuthorizeRequestId)
            && possibleAuthorizeRequestId.Count == 1
            && !string.IsNullOrWhiteSpace(authorizeRequestId = possibleAuthorizeRequestId.ToString()))
        {
            var authorizeRequestParameters = await AuthorizeRequestParameters.ReadAsync(requestContext, authorizeRequestId, cancellationToken);
            if (authorizeRequestParameters != null)
            {
                return new(authorizeRequestId, authorizeRequestParameters);
            }
        }

        return new(new(AuthorizeErrors.InvalidRequest, "Authorize request not found"));
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

        var errorToSave = new UnredirectableError(validationError.ProtocolError, validationError.Client?.GetClientId(), validationError.RedirectUri, validationError.ResponseMode, validationError.Issuer);
        var errorId = await ErrorService.SaveAsync(requestContext, errorToSave, cancellationToken);
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
            var authorizeRequestId = await AuthorizeRequestParameters.SaveAsync(requestContext, authorizeRequest.InitialRequestDate, authorizeRequest.Raw, cancellationToken);
            return new DefaultLoginUserPageResult(FrameworkOptions, authorizeRequestId);
        }

        if (requiredInteraction == DefaultInteractionResult.Consent)
        {
            var authorizeRequestId = await AuthorizeRequestParameters.SaveAsync(requestContext, authorizeRequest.InitialRequestDate, authorizeRequest.Raw, cancellationToken);
            return new DefaultConsentPageResult(FrameworkOptions, authorizeRequestId);
        }

        return await HandlerErrorAsync(requestContext, new(AuthorizeErrors.ServerError, "Incorrect interaction state"), authorizeRequest, cancellationToken);
    }

    protected virtual async Task<IEndpointHandlerResult> HandleErrorWithoutRedirectAsync(
        TRequestContext requestContext,
        ProtocolError protocolError,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        cancellationToken.ThrowIfCancellationRequested();
        var errorToSave = new UnredirectableError(protocolError, null, null, null, issuer);
        var errorId = await ErrorService.SaveAsync(requestContext, errorToSave, cancellationToken);
        return new DefaultErrorPageResult(FrameworkOptions, errorId);
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

        var errorToSave = new UnredirectableError(protocolError, authorizeRequest.Client.GetClientId(), authorizeRequest.RedirectUriToUse, authorizeRequest.ResponseMode, authorizeRequest.Issuer);
        var errorId = await ErrorService.SaveAsync(requestContext, errorToSave, cancellationToken);
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
