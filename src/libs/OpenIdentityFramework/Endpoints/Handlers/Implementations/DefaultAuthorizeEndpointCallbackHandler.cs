using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Endpoints.Results.Implementations;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultAuthorizeEndpointCallbackHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestError, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizeRequest, TAuthorizeRequestConsent>
    : IAuthorizeEndpointCallbackHandler<TRequestContext>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizeRequestError : AbstractAuthorizeRequestError
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
    where TAuthorizeRequest : AbstractAuthorizeRequest
    where TAuthorizeRequestConsent : AbstractAuthorizeRequestConsent<TResourceOwnerIdentifiers>
{
    public DefaultAuthorizeEndpointCallbackHandler(
        OpenIdentityFrameworkOptions frameworkOptions,
        IIssuerUrlProvider<TRequestContext> issuerUrlProvider,
        IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> requestValidator,
        HtmlEncoder htmlEncoder,
        IAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError> errorService,
        IResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> resourceOwnerAuthentication,
        IAuthorizeRequestService<TRequestContext, TAuthorizeRequest> authorizeRequest,
        IAuthorizeRequestConsentService<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers> authorizeRequestConsent,
        IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestConsent, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> interactionService,
        IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> responseGenerator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(issuerUrlProvider);
        ArgumentNullException.ThrowIfNull(requestValidator);
        ArgumentNullException.ThrowIfNull(htmlEncoder);
        ArgumentNullException.ThrowIfNull(errorService);
        ArgumentNullException.ThrowIfNull(resourceOwnerAuthentication);
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(authorizeRequestConsent);
        ArgumentNullException.ThrowIfNull(interactionService);
        ArgumentNullException.ThrowIfNull(responseGenerator);
        FrameworkOptions = frameworkOptions;
        IssuerUrlProvider = issuerUrlProvider;
        RequestValidator = requestValidator;
        HtmlEncoder = htmlEncoder;
        ErrorService = errorService;
        ResourceOwnerAuthentication = resourceOwnerAuthentication;
        AuthorizeRequest = authorizeRequest;
        AuthorizeRequestConsent = authorizeRequestConsent;
        InteractionService = interactionService;
        ResponseGenerator = responseGenerator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IIssuerUrlProvider<TRequestContext> IssuerUrlProvider { get; }
    protected IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> RequestValidator { get; }
    protected HtmlEncoder HtmlEncoder { get; }
    protected IAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError> ErrorService { get; }
    protected IResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> ResourceOwnerAuthentication { get; }
    protected IAuthorizeRequestService<TRequestContext, TAuthorizeRequest> AuthorizeRequest { get; }
    protected IAuthorizeRequestConsentService<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers> AuthorizeRequestConsent { get; }
    protected IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestConsent, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> InteractionService { get; }
    protected IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> ResponseGenerator { get; }

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

        var requestReadResult = await ReadRequestAsync(requestContext, queryParameters, cancellationToken);
        if (requestReadResult.HasError)
        {
            return await HandleErrorWithoutRedirectAsync(requestContext, requestReadResult.ProtocolError, issuer, cancellationToken);
        }

        var validationResult = await RequestValidator.ValidateAsync(
            requestContext,
            requestReadResult.Request.GetAuthorizeRequestParameters(),
            requestReadResult.Request.GetInitialRequestDate(),
            issuer,
            cancellationToken);
        if (validationResult.HasError)
        {
            await AuthorizeRequest.DeleteAsync(requestContext, requestReadResult.RequestId, cancellationToken);
            return await HandleValidationErrorAsync(requestContext, validationResult.ValidationError, cancellationToken);
        }

        var authenticationResult = await ResourceOwnerAuthentication.AuthenticateAsync(requestContext, cancellationToken);
        if (authenticationResult.HasError)
        {
            await AuthorizeRequest.DeleteAsync(requestContext, requestReadResult.RequestId, cancellationToken);
            var authenticationError = new ProtocolError(AuthorizeErrors.ServerError, authenticationResult.ErrorDescription);
            return await HandleErrorAsync(requestContext, authenticationError, validationResult.ValidRequest, cancellationToken);
        }

        TAuthorizeRequestConsent? requestConsent = null;
        if (authenticationResult.IsAuthenticated)
        {
            requestConsent = await AuthorizeRequestConsent.FindAsync(requestContext, requestReadResult.RequestId, authenticationResult.Authentication.EssentialClaims.GetResourceOwnerIdentifiers(), cancellationToken);
        }

        var interactionResult = await InteractionService.ProcessInteractionRequirementsAsync(
            requestContext,
            validationResult.ValidRequest,
            authenticationResult.Authentication,
            requestConsent,
            cancellationToken);
        if (interactionResult.HasError)
        {
            await AuthorizeRequest.DeleteAsync(requestContext, requestReadResult.RequestId, cancellationToken);
            return await HandleErrorAsync(requestContext, interactionResult.ProtocolError, validationResult.ValidRequest, cancellationToken);
        }

        if (interactionResult.HasRequiredInteraction)
        {
            return await HandleRequiredInteraction(requestContext, requestReadResult.RequestId, interactionResult.RequiredInteraction, validationResult.ValidRequest, cancellationToken);
        }

        if (!interactionResult.HasValidRequest)
        {
            await AuthorizeRequest.DeleteAsync(requestContext, requestReadResult.RequestId, cancellationToken);
            return await HandleErrorAsync(requestContext, new(AuthorizeErrors.ServerError, "Incorrect interaction state"), validationResult.ValidRequest, cancellationToken);
        }

        var responseResult = await ResponseGenerator.CreateResponseAsync(requestContext, interactionResult.ValidRequest, cancellationToken);
        if (responseResult.HasError)
        {
            await AuthorizeRequest.DeleteAsync(requestContext, requestReadResult.RequestId, cancellationToken);
            return await HandleErrorAsync(requestContext, new(AuthorizeErrors.ServerError, responseResult.ErrorDescription), validationResult.ValidRequest, cancellationToken);
        }

        await AuthorizeRequest.DeleteAsync(requestContext, requestReadResult.RequestId, cancellationToken);
        var successfulResponseParameters = BuildSuccessfulResponseParameters(responseResult.AuthorizeResponse);
        return new DefaultDirectAuthorizeResult(
            FrameworkOptions,
            HtmlEncoder,
            successfulResponseParameters,
            interactionResult.ValidRequest.AuthorizeRequest.RedirectUriToUse,
            interactionResult.ValidRequest.AuthorizeRequest.ResponseMode);
    }

    protected virtual async Task<AuthorizeRequestReadResult> ReadRequestAsync(
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
            var authorizeRequest = await AuthorizeRequest.FindAsync(requestContext, authorizeRequestId, cancellationToken);
            if (authorizeRequest != null)
            {
                return new(authorizeRequestId, authorizeRequest);
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
        string authorizeRequestId,
        string requiredInteraction,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        if (requiredInteraction == DefaultInteractionResult.Login)
        {
            return new DefaultLoginUserPageResult(FrameworkOptions, authorizeRequestId);
        }

        if (requiredInteraction == DefaultInteractionResult.Consent)
        {
            return new DefaultConsentPageResult(FrameworkOptions, authorizeRequestId);
        }

        return await HandleErrorAsync(requestContext, new(AuthorizeErrors.ServerError, "Incorrect interaction state"), authorizeRequest, cancellationToken);
    }

    protected virtual async Task<IEndpointHandlerResult> HandleErrorWithoutRedirectAsync(
        TRequestContext requestContext,
        ProtocolError protocolError,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        cancellationToken.ThrowIfCancellationRequested();
        var errorId = await ErrorService.CreateAsync(
            requestContext,
            protocolError,
            null,
            null,
            null,
            null,
            issuer,
            cancellationToken);
        return new DefaultErrorPageResult(FrameworkOptions, errorId);
    }

    protected virtual async Task<IEndpointHandlerResult> HandleErrorAsync(
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

    protected class AuthorizeRequestReadResult
    {
        public AuthorizeRequestReadResult(ProtocolError protocolError)
        {
            ArgumentNullException.ThrowIfNull(protocolError);
            ProtocolError = protocolError;
            HasError = true;
        }

        public AuthorizeRequestReadResult(string requestId, TAuthorizeRequest request)
        {
            ArgumentNullException.ThrowIfNull(requestId);
            ArgumentNullException.ThrowIfNull(request);
            RequestId = requestId;
            Request = request;
        }

        public string? RequestId { get; }

        public TAuthorizeRequest? Request { get; }

        public ProtocolError? ProtocolError { get; }

        [MemberNotNullWhen(true, nameof(ProtocolError))]
        [MemberNotNullWhen(false, nameof(Request))]
        [MemberNotNullWhen(false, nameof(RequestId))]
        public bool HasError { get; }
    }
}
