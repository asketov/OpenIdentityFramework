using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Requests.Authorize;
using OpenIdentityFramework.Constants.Responses.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAuthorizeRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : IAuthorizeRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultAuthorizeRequestValidator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IClientService<TClient, TClientSecret> clients,
        IResourceValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret> resourceValidator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(clients);
        ArgumentNullException.ThrowIfNull(resourceValidator);
        FrameworkOptions = frameworkOptions;
        Clients = clients;
        ResourceValidator = resourceValidator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IClientService<TClient, TClientSecret> Clients { get; }
    protected IResourceValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret> ResourceValidator { get; }

    public virtual async Task<AuthorizeRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> ValidateAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset initialRequestDate,
        string issuer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var isOpenIdRequest = await IsOpenIdConnectRequestAsync(httpContext, parameters, cancellationToken);
        var coreParametersValidation = await ValidateCoreParametersAsync(
            httpContext,
            parameters,
            initialRequestDate,
            issuer,
            isOpenIdRequest,
            cancellationToken);
        if (coreParametersValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError<TClient, TClientSecret>(
                initialRequestDate,
                issuer,
                coreParametersValidation.Error));
        }

        var coreParameters = coreParametersValidation.Value;
        var scopeValidation = await ValidateScopeAsync(httpContext, parameters, coreParametersValidation.Value.Client, isOpenIdRequest, cancellationToken);
        if (scopeValidation.HasError)
        {
            return coreParameters.BuildError(scopeValidation.Error);
        }

        var codeChallengeMethodValidation = await ValidateCodeChallengeMethodAsync(httpContext, parameters, coreParameters.Client, cancellationToken);
        if (codeChallengeMethodValidation.HasError)
        {
            return coreParameters.BuildError(codeChallengeMethodValidation.Error);
        }

        var codeChallengeValidation = await ValidateCodeChallengeAsync(httpContext, parameters, coreParameters.Client, cancellationToken);
        if (codeChallengeValidation.HasError)
        {
            return coreParameters.BuildError(codeChallengeValidation.Error);
        }

        if (!isOpenIdRequest)
        {
            return new(new ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                initialRequestDate,
                issuer,
                coreParameters.Client,
                coreParameters.RedirectUri,
                scopeValidation.ValidResources,
                codeChallengeValidation.CodeChallenge,
                codeChallengeMethodValidation.CodeChallengeMethod,
                coreParameters.ResponseType,
                coreParameters.GrantType,
                coreParameters.State,
                coreParameters.ResponseMode,
                parameters));
        }

        var nonceValidation = await ValidateNonceAsync(httpContext, parameters, coreParameters.GrantType, cancellationToken);
        if (nonceValidation.HasError)
        {
            return coreParameters.BuildError(nonceValidation.Error);
        }

        var promptValidation = await ValidatePromptAsync(httpContext, parameters, cancellationToken);
        if (promptValidation.HasError)
        {
            return coreParameters.BuildError(promptValidation.Error);
        }

        var maxAgeValidation = await ValidateMaxAgeAsync(httpContext, parameters, cancellationToken);
        if (maxAgeValidation.HasError)
        {
            return coreParameters.BuildError(maxAgeValidation.Error);
        }

        var loginHintValidation = await ValidateLoginHintAsync(httpContext, parameters, cancellationToken);
        if (loginHintValidation.HasError)
        {
            return coreParameters.BuildError(loginHintValidation.Error);
        }

        var acrValuesValidation = await ValidateAcrValuesAsync(httpContext, parameters, cancellationToken);
        if (acrValuesValidation.HasError)
        {
            return coreParameters.BuildError(acrValuesValidation.Error);
        }

        var displayValidation = await ValidateDisplayAsync(httpContext, parameters, cancellationToken);
        if (displayValidation.HasError)
        {
            return coreParameters.BuildError(displayValidation.Error);
        }

        var uiLocalesValidation = await ValidateUiLocalesAsync(httpContext, parameters, cancellationToken);
        if (uiLocalesValidation.HasError)
        {
            return coreParameters.BuildError(uiLocalesValidation.Error);
        }

        var requestValidation = ValidateRequest(parameters);
        if (requestValidation.HasError)
        {
            return coreParameters.BuildError(requestValidation.Error);
        }

        var requestUriValidation = ValidateRequestUri(parameters);
        if (requestUriValidation.HasError)
        {
            return coreParameters.BuildError(requestUriValidation.Error);
        }

        var registrationValidation = ValidateRegistration(parameters);
        if (registrationValidation.HasError)
        {
            return coreParameters.BuildError(registrationValidation.Error);
        }

        return new(new ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            initialRequestDate,
            issuer,
            coreParameters.Client,
            coreParameters.RedirectUri,
            scopeValidation.ValidResources,
            codeChallengeValidation.CodeChallenge,
            codeChallengeMethodValidation.CodeChallengeMethod,
            coreParameters.ResponseType,
            coreParameters.GrantType,
            coreParameters.State,
            coreParameters.ResponseMode,
            nonceValidation.Nonce,
            displayValidation.Display,
            promptValidation.Prompt,
            maxAgeValidation.MaxAge,
            uiLocalesValidation.UiLocales,
            loginHintValidation.LoginHint,
            acrValuesValidation.AcrValues,
            parameters));
    }

    protected virtual async Task<CoreParametersValidationResult> ValidateCoreParametersAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset requestDate,
        string issuer,
        bool isOpenIdRequest,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var clientValidation = await ValidateClientAsync(httpContext, parameters, cancellationToken);
        if (clientValidation.HasError)
        {
            return new(clientValidation.Error);
        }

        var responseTypeValidation = await ValidateResponseTypeAsync(httpContext, parameters, clientValidation.Client, isOpenIdRequest, cancellationToken);
        if (responseTypeValidation.HasError)
        {
            return new(responseTypeValidation.Error);
        }

        var stateValidation = await ValidateStateAsync(httpContext, parameters, cancellationToken);
        if (stateValidation.HasError)
        {
            return new(stateValidation.Error);
        }

        var responseModeValidation = await ValidateResponseModeAsync(httpContext, parameters, responseTypeValidation.ResponseType, cancellationToken);
        if (responseModeValidation.HasError)
        {
            return new(responseModeValidation.Error);
        }

        var redirectUriValidation = await ValidateRedirectUriAsync(httpContext, parameters, clientValidation.Client, isOpenIdRequest, cancellationToken);
        if (redirectUriValidation.HasError)
        {
            return new(redirectUriValidation.Error);
        }

        return new(new CoreParameters(
            requestDate,
            issuer,
            clientValidation.Client,
            responseTypeValidation.ResponseType,
            responseTypeValidation.GrantType,
            stateValidation.State,
            responseModeValidation.ResponseMode,
            redirectUriValidation.RedirectUri));
    }

    protected virtual Task<bool> IsOpenIdConnectRequestAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // "scope" is optional, but
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // If the client omits the scope parameter when requesting authorization,
        // the authorization server MUST either process the request using a pre-defined default value or fail the request indicating an invalid scope.
        // The authorization server SHOULD document its scope requirements and default value (if defined).
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "scope" - REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
        // If the "openid" scope value is not present, the behavior is entirely unspecified.
        // Other scope values MAY be present.
        // Scope values used that are not understood by an implementation SHOULD be ignored.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (!parameters.TryGetValue(RequestParameters.Scope, out var scopeValues) || scopeValues.Count == 0)
        {
            return Task.FromResult(false);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (scopeValues.Count != 1)
        {
            return Task.FromResult(false);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var scope = scopeValues.ToString();
        if (string.IsNullOrEmpty(scope))
        {
            return Task.FromResult(false);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // The value of the scope parameter is expressed as a list of space- delimited, case-sensitive strings.
        // https://learn.microsoft.com/en-us/dotnet/standard/base-types/best-practices-strings#recommendations-for-string-usage
        // Use the non-linguistic StringComparison.Ordinal or StringComparison.OrdinalIgnoreCase values instead of string operations based on CultureInfo.InvariantCulture
        // when the comparison is linguistically irrelevant (symbolic, for example).
        var requestedScopes = scope.Split(' ').ToHashSet(StringComparer.Ordinal);

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "scope" - REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
        var isOpenIdRequest = requestedScopes.Contains(DefaultScopes.OpenId);
        return Task.FromResult(isOpenIdRequest);
    }

    protected virtual async Task<ClientValidationResult> ValidateClientAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "client_id" - REQUIRED.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (!parameters.TryGetValue(RequestParameters.ClientId, out var clientIdValues) || clientIdValues.Count == 0)
        {
            return ClientValidationResult.ClientIdIsMissing;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (clientIdValues.Count != 1)
        {
            return ClientValidationResult.MultipleClientIdValuesNotAllowed;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var clientId = clientIdValues.ToString();
        if (string.IsNullOrEmpty(clientId))
        {
            return ClientValidationResult.ClientIdIsMissing;
        }

        // length check
        if (clientId.Length > FrameworkOptions.InputLengthRestrictions.ClientId)
        {
            return ClientValidationResult.ClientIdIsTooLong;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.1
        // "client_id" syntax validation
        if (!ClientIdSyntaxValidator.IsValid(clientId))
        {
            return ClientValidationResult.InvalidClientIdSyntax;
        }

        // client not found
        var client = await Clients.FindAsync(httpContext, clientId, cancellationToken);
        if (client == null)
        {
            return ClientValidationResult.UnknownOrDisabledClient;
        }

        return new(client);
    }

    protected virtual Task<ResponseTypeValidationResult> ValidateResponseTypeAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client,
        bool isOpenIdRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1 (Authorization Code)
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1 (Authorization Code)
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.1 (Hybrid Flow)
        // response_type - REQUIRED in both specs
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (!parameters.TryGetValue(RequestParameters.ResponseType, out var responseTypeValues) || responseTypeValues.Count == 0)
        {
            return Task.FromResult(ResponseTypeValidationResult.ResponseTypeIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (responseTypeValues.Count != 1)
        {
            return Task.FromResult(ResponseTypeValidationResult.MultipleResponseTypeValuesNotAllowed);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var responseType = responseTypeValues.ToString();
        if (string.IsNullOrEmpty(responseType))
        {
            return Task.FromResult(ResponseTypeValidationResult.ResponseTypeIsMissing);
        }

        var allowedGrantTypes = client.GetAllowedGrantTypes();

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // This specification defines the value "code", which must be used to signal that the client wants to use the authorization code flow.
        // Extension response types MAY contain a space-delimited (%x20) list of values, where the order of values does not matter (e.g., response type "a b" is the same as "b a").
        // The meaning of such composite response types is defined by their respective specifications.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // When using the Authorization Code Flow, this value is "code".
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.1
        // When using the Hybrid Flow, this value is "code id_token", "code token", or "code id_token token"
        // ==================================
        // OAuth 2.1 deprecates the issuance of tokens directly from the authorization endpoint. Only 'code id_token' is compatible with OAuth 2.1 and OpenID Connect 1.0
        // OpenID Connect 1.0-specific
        if (isOpenIdRequest && responseType.Contains(' ', StringComparison.Ordinal))
        {
            var multipleResponseTypes = responseType.Split(' ');
            if (multipleResponseTypes.Except(ResponseType.HybridFlow).Any())
            {
                return Task.FromResult(ResponseTypeValidationResult.UnsupportedResponseType);
            }

            if (allowedGrantTypes.Contains(DefaultGrantTypes.Hybrid))
            {
                return Task.FromResult(ResponseTypeValidationResult.CodeIdToken);
            }

            return Task.FromResult(ResponseTypeValidationResult.UnsupportedResponseType);
        }

        // Both OAuth 2.1 and OpenID Connect 1.0
        if (responseType == ResponseType.Code && allowedGrantTypes.Contains(DefaultGrantTypes.AuthorizationCode))
        {
            return Task.FromResult(ResponseTypeValidationResult.Code);
        }

        return Task.FromResult(ResponseTypeValidationResult.UnsupportedResponseType);
    }

    protected virtual Task<StateValidationResult> ValidateStateAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "state" - OPTIONAL (OAuth 2.1) / RECOMMENDED (OpenID Connect 1.0).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (!parameters.TryGetValue(RequestParameters.State, out var stateValues) || stateValues.Count == 0)
        {
            return Task.FromResult(StateValidationResult.Null);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (stateValues.Count != 1)
        {
            return Task.FromResult(StateValidationResult.MultipleStateValuesNotAllowed);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var state = stateValues.ToString();
        if (string.IsNullOrEmpty(state))
        {
            return Task.FromResult(StateValidationResult.Null);
        }

        // length check
        if (state.Length > FrameworkOptions.InputLengthRestrictions.State)
        {
            return Task.FromResult(StateValidationResult.StateIsTooLong);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.1
        // "client_id" syntax validation
        if (!StateSyntaxValidator.IsValid(state))
        {
            return Task.FromResult(StateValidationResult.InvalidStateSyntax);
        }

        var stateResult = new StateValidationResult(state);
        return Task.FromResult(stateResult);
    }

    protected virtual Task<ResponseModeValidationResult> ValidateResponseModeAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        string responseType,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "response_mode" - OPTIONAL (OAuth 2.0, OpenID Connect 1.0).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (!parameters.TryGetValue(RequestParameters.ResponseMode, out var responseModeValues) || responseModeValues.Count == 0)
        {
            return Task.FromResult(InferResponseMode(responseType));
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (responseModeValues.Count != 1)
        {
            return Task.FromResult(ResponseModeValidationResult.MultipleResponseModeValuesNotAllowed);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var responseMode = responseModeValues.ToString();
        if (string.IsNullOrEmpty(responseMode))
        {
            return Task.FromResult(InferResponseMode(responseType));
        }

        return Task.FromResult(ResponseModeToResult(responseMode));

        static ResponseModeValidationResult InferResponseMode(string responseType)
        {
            if (ResponseType.ToResponseMode.TryGetValue(responseType, out var inferredResponseMode))
            {
                return ResponseModeToResult(inferredResponseMode);
            }

            return ResponseModeValidationResult.UnableToInferResponseMode;
        }

        static ResponseModeValidationResult ResponseModeToResult(string responseMode)
        {
            // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#rfc.section.2.1
            // https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#rfc.section.2
            if (responseMode == ResponseMode.Fragment)
            {
                return ResponseModeValidationResult.Fragment;
            }

            if (responseMode == ResponseMode.Query)
            {
                return ResponseModeValidationResult.Query;
            }

            if (responseMode == ResponseMode.FormPost)
            {
                return ResponseModeValidationResult.FormPost;
            }

            return ResponseModeValidationResult.UnsupportedResponseMode;
        }
    }

    protected virtual Task<RedirectUriValidationResult> ValidateRedirectUriAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client,
        bool isOpenIdRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.3.1
        // Authorization servers MUST require clients to register their complete redirect URI (including the path component).
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider
        var preRegisteredRedirectUris = client.GetPreRegisteredRedirectUris();
        if (preRegisteredRedirectUris.Count < 1)
        {
            return Task.FromResult(RedirectUriValidationResult.NoPreRegisteredRedirectUrisInClientConfiguration);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // "redirect_uri" - OPTIONAL
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "redirect_uri" - REQUIRED.
        if (!parameters.TryGetValue(RequestParameters.RedirectUri, out var redirectUriValues) || redirectUriValues.Count == 0)
        {
            return Task.FromResult(InferRedirectUri(isOpenIdRequest, preRegisteredRedirectUris));
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (redirectUriValues.Count != 1)
        {
            return Task.FromResult(RedirectUriValidationResult.MultipleRedirectUriValuesNotAllowed);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var redirectUriString = redirectUriValues.ToString();
        if (string.IsNullOrEmpty(redirectUriString))
        {
            return Task.FromResult(InferRedirectUri(isOpenIdRequest, preRegisteredRedirectUris));
        }

        // length check
        if (redirectUriString.Length > FrameworkOptions.InputLengthRestrictions.RedirectUri)
        {
            return Task.FromResult(RedirectUriValidationResult.RedirectUriIsTooLong);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.3
        if (!ClientRedirectUriSyntaxValidator.IsValid(redirectUriString, out var redirectUri))
        {
            return Task.FromResult(RedirectUriValidationResult.InvalidRedirectUriSyntax);
        }

        // OpenID Connect 1.0
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // redirect_uri - REQUIRED. This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider,
        // with the matching performed as described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
        // When using this flow, the Redirection URI SHOULD use the https scheme; however, it MAY use the http scheme, provided that the Client Type is confidential.
        // The Redirection URI MAY use an alternate scheme, such as one that is intended to identify a callback into a native application.
        // https://learn.microsoft.com/en-us/dotnet/standard/base-types/best-practices-strings#recommendations-for-string-usage
        // Use the non-linguistic StringComparison.Ordinal or StringComparison.OrdinalIgnoreCase values instead of string operations based on CultureInfo.InvariantCulture
        // when the comparison is linguistically irrelevant (symbolic, for example).
        if (isOpenIdRequest)
        {
            // Exact match for OIDC
            if (preRegisteredRedirectUris.Contains(redirectUriString, StringComparer.Ordinal))
            {
                // http scheme only for confidential clients
                if (redirectUri.Scheme == Uri.UriSchemeHttp && !client.IsConfidential())
                {
                    return Task.FromResult(RedirectUriValidationResult.InvalidRedirectUri);
                }

                return Task.FromResult(new RedirectUriValidationResult(redirectUriString));
            }

            return Task.FromResult(RedirectUriValidationResult.InvalidRedirectUri);
        }

        // OAuth 2.1
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-1.5
        // OAuth URLs MUST use the https scheme except for loopback interface redirect URIs, which MAY use the http scheme.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.3.1
        // Authorization servers MUST require clients to register their complete redirect URI (including the path component).
        // Authorization servers MUST reject authorization requests that specify a redirect URI that doesn't exactly match one that was registered,
        // with an exception for loopback redirects, where an exact match is required except for the port URI component.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // In particular, the authorization server MUST validate the redirect_uri in the request if present,
        // ensuring that it matches one of the registered redirect URIs previously established during client registration (Section 2).
        // When comparing the two URIs the authorization server MUST using simple character-by-character string comparison as defined in [RFC3986], Section 6.2.1.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-7.5.1
        // Loopback interface redirect URIs MAY use the http scheme (i.e., without TLS). This is acceptable for loopback interface redirect URIs as the HTTP request never leaves the device.
        // Clients should use loopback IP literals rather than the string localhost as described in Section 8.4.2.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-8.4.2
        // While redirect URIs using the name localhost (i.e., http://localhost:{port}/{path}) function similarly to loopback IP redirects, the use of localhost is NOT RECOMMENDED.
        // The authorization server MUST allow any port to be specified at the time of the request for loopback IP redirect URIs,
        // to accommodate clients that obtain an available ephemeral port from the operating system at the time of the request.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-8.4.3
        // To perform an authorization request with a private-use URI scheme redirect, the native app launches the browser with a standard authorization request,
        // but one where the redirect URI utilizes a private-use URI scheme it registered with the operating system.
        if (redirectUri.IsLoopback)
        {
            foreach (var preRegisteredRedirectUri in preRegisteredRedirectUris)
            {
                // Ignore port for loopback
                if (ClientRedirectUriSyntaxValidator.IsValid(preRegisteredRedirectUri, out var clientRedirectUri)
                    && clientRedirectUri.IsLoopback
                    && clientRedirectUri.IsWellFormedOriginalString()
                    && clientRedirectUri.Scheme == redirectUri.Scheme
                    && clientRedirectUri.Host == redirectUri.Host
                    && clientRedirectUri.PathAndQuery == redirectUri.PathAndQuery
                    && string.IsNullOrEmpty(clientRedirectUri.Fragment)
                    && string.IsNullOrEmpty(redirectUri.Fragment))
                {
                    return Task.FromResult(new RedirectUriValidationResult(redirectUriString));
                }
            }

            return Task.FromResult(RedirectUriValidationResult.InvalidRedirectUri);
        }

        // OAuth 2.1 non-loopback didn't allow http
        if (!redirectUri.IsLoopback
            && redirectUri.Scheme != Uri.UriSchemeHttp
            && preRegisteredRedirectUris.Contains(redirectUriString, StringComparer.Ordinal))
        {
            return Task.FromResult(new RedirectUriValidationResult(redirectUriString));
        }

        return Task.FromResult(RedirectUriValidationResult.InvalidRedirectUri);


        static RedirectUriValidationResult InferRedirectUri(bool isOpenIdRequest, IReadOnlySet<string> clientRedirectUris)
        {
            if (!isOpenIdRequest)
            {
                if (clientRedirectUris.Count == 1)
                {
                    return new(clientRedirectUris.Single());
                }

                // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.3.2
                // If multiple redirect URIs have been registered, the client MUST include a redirect URI with the authorization request using the redirect_uri request parameter.
                return RedirectUriValidationResult.InvalidRedirectUri;
            }

            return RedirectUriValidationResult.RedirectUriIsMissing;
        }
    }

    protected virtual async Task<ScopeValidationResult> ValidateScopeAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client,
        bool isOpenIdRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // "scope" - OPTIONAL. The scope of the access request as described by Section 3.2.2.1.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // If the client omits the scope parameter when requesting authorization, the authorization server MUST either process the request using a pre-defined default value or fail the request indicating an invalid scope.
        // The authorization server SHOULD document its scope requirements and default value (if defined).
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // REQUIRED. OpenID Connect requests MUST contain the "openid" scope value. If the openid scope value is not present, the behavior is entirely unspecified.
        // Other scope values MAY be present. Scope values used that are not understood by an implementation SHOULD be ignored.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        string scopeParameterValue;
        if (!parameters.TryGetValue(RequestParameters.Scope, out var scopeValues)
            || scopeValues.Count == 0
            || string.IsNullOrEmpty(scopeParameterValue = scopeValues.ToString()))
        {
            if (!isOpenIdRequest)
            {
                var defaultScopesValidation = await ResourceValidator.ValidateRequestedScopesAsync(
                    httpContext,
                    client,
                    client.GetAllowedScopes(),
                    DefaultTokenTypes.OAuth,
                    cancellationToken);
                if (defaultScopesValidation.HasError)
                {
                    if (defaultScopesValidation.Error.HasConfigurationError)
                    {
                        return ScopeValidationResult.Misconfigured;
                    }

                    return ScopeValidationResult.InvalidScope;
                }

                return new(defaultScopesValidation.Valid);
            }

            return ScopeValidationResult.ScopeIsMissing;
        }


        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (scopeValues.Count != 1)
        {
            return ScopeValidationResult.MultipleScope;
        }

        // length check
        if (scopeParameterValue.Length > FrameworkOptions.InputLengthRestrictions.Scope)
        {
            return ScopeValidationResult.ScopeIsTooLong;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings. The strings are defined by the authorization server.
        // If the value contains multiple space-delimited strings, their order does not matter, and each string adds an additional access range to the requested scope.
        var requestedScopes = scopeParameterValue
            .Split(' ')
            .ToHashSet(StringComparer.Ordinal);
        foreach (var requestedScope in requestedScopes)
        {
            // syntax validation
            if (string.IsNullOrEmpty(requestedScope) && !ScopeSyntaxValidator.IsValid(requestedScope))
            {
                return ScopeValidationResult.InvalidScopeSyntax;
            }

            // length check
            if (requestedScope.Length > FrameworkOptions.InputLengthRestrictions.ScopeSingleEntry)
            {
                return ScopeValidationResult.ScopeIsTooLong;
            }
        }

        var allowedTokenTypes = DefaultTokenTypes.OAuth;
        if (isOpenIdRequest)
        {
            allowedTokenTypes = DefaultTokenTypes.OpenIdConnect;
        }

        var requestedScopesValidation = await ResourceValidator.ValidateRequestedScopesAsync(httpContext, client, requestedScopes, allowedTokenTypes, cancellationToken);
        if (requestedScopesValidation.HasError)
        {
            if (requestedScopesValidation.Error.HasConfigurationError)
            {
                return ScopeValidationResult.Misconfigured;
            }

            return ScopeValidationResult.InvalidScope;
        }

        return new(requestedScopesValidation.Valid);
    }

    protected virtual Task<CodeChallengeMethodValidationResult> ValidateCodeChallengeMethodAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // "code_challenge_method" - OPTIONAL, defaults to "plain" if not present in the request. Code verifier transformation method is "S256" or "plain".
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var allowedCodeChallengeMethods = client.GetAllowedCodeChallengeMethods();
        if (!parameters.TryGetValue(RequestParameters.CodeChallengeMethod, out var codeChallengeMethodValues) || codeChallengeMethodValues.Count == 0)
        {
            if (allowedCodeChallengeMethods.Contains(CodeChallengeMethod.Plain))
            {
                return Task.FromResult(CodeChallengeMethodValidationResult.Plain);
            }

            return Task.FromResult(CodeChallengeMethodValidationResult.CodeChallengeMethodIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeChallengeMethodValues.Count != 1)
        {
            return Task.FromResult(CodeChallengeMethodValidationResult.MultipleCodeChallengeMethod);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var codeChallengeMethod = codeChallengeMethodValues.ToString();
        if (string.IsNullOrEmpty(codeChallengeMethod))
        {
            if (allowedCodeChallengeMethods.Contains(CodeChallengeMethod.Plain))
            {
                return Task.FromResult(CodeChallengeMethodValidationResult.Plain);
            }

            return Task.FromResult(CodeChallengeMethodValidationResult.CodeChallengeMethodIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // Code verifier transformation method is "S256" or "plain".
        if (codeChallengeMethod == CodeChallengeMethod.Plain && allowedCodeChallengeMethods.Contains(codeChallengeMethod))
        {
            return Task.FromResult(CodeChallengeMethodValidationResult.Plain);
        }

        if (codeChallengeMethod == CodeChallengeMethod.S256 && allowedCodeChallengeMethods.Contains(codeChallengeMethod))
        {
            return Task.FromResult(CodeChallengeMethodValidationResult.S256);
        }

        return Task.FromResult(CodeChallengeMethodValidationResult.UnknownCodeChallengeMethod);
    }

    protected virtual Task<CodeChallengeValidationResult> ValidateCodeChallengeAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-7.6.1
        // To prevent injection of authorization codes into the client, using code_challenge and code_verifier is REQUIRED for clients,
        // and authorization servers MUST enforce their use, unless both of the following criteria are met:
        // * The client is a confidential client.
        // * In the specific deployment and the specific request, there is reasonable assurance by the authorization server that the client implements the OpenID Connect "nonce" mechanism properly.
        // In this case, using and enforcing code_challenge and code_verifier is still RECOMMENDED.
        // ------
        // In current implementation "code_challenge" is required.
        if (!parameters.TryGetValue(RequestParameters.CodeChallenge, out var codeChallengeValues) || codeChallengeValues.Count == 0)
        {
            return Task.FromResult(CodeChallengeValidationResult.CodeChallengeIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeChallengeValues.Count != 1)
        {
            return Task.FromResult(CodeChallengeValidationResult.MultipleCodeChallenge);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var codeChallenge = codeChallengeValues.ToString();
        if (string.IsNullOrEmpty(codeChallenge))
        {
            return Task.FromResult(CodeChallengeValidationResult.CodeChallengeIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
        if (codeChallenge.Length < 43)
        {
            return Task.FromResult(CodeChallengeValidationResult.CodeChallengeIsTooShort);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
        if (codeChallenge.Length > 128)
        {
            return Task.FromResult(CodeChallengeValidationResult.CodeChallengeIsTooLong);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
        if (!CodeChallengeSyntaxValidator.IsValid(codeChallenge))
        {
            return Task.FromResult(CodeChallengeValidationResult.InvalidCodeChallengeSyntax);
        }

        return Task.FromResult(new CodeChallengeValidationResult(codeChallenge));
    }

    protected virtual Task<NonceValidationResult> ValidateNonceAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        string grantType,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(parameters);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "nonce" - OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        // The value is passed through unmodified from the Authentication Request to the ID Token.
        // Sufficient entropy MUST be present in the nonce values used to prevent attackers from guessing values.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11
        // nonce - Use of the "nonce" Claim is REQUIRED for this flow (hybrid).
        if (!parameters.TryGetValue(RequestParameters.Nonce, out var nonceValues) || nonceValues.Count == 0)
        {
            return Task.FromResult(InferDefaultResult(grantType));
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (nonceValues.Count != 1)
        {
            return Task.FromResult(NonceValidationResult.MultipleNonce);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var nonce = nonceValues.ToString();
        if (string.IsNullOrEmpty(nonce))
        {
            return Task.FromResult(InferDefaultResult(grantType));
        }

        // length check
        if (nonce.Length > FrameworkOptions.InputLengthRestrictions.Nonce)
        {
            return Task.FromResult(NonceValidationResult.NonceIsTooLong);
        }

        return Task.FromResult(new NonceValidationResult(nonce));

        static NonceValidationResult InferDefaultResult(string grantType)
        {
            if (grantType == DefaultGrantTypes.Hybrid)
            {
                return NonceValidationResult.NonceIsMissing;
            }

            return NonceValidationResult.Null;
        }
    }

    protected virtual Task<PromptValidationResult> ValidatePromptAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "prompt" - OPTIONAL. Space delimited, case sensitive list of ASCII string values
        // that specifies whether the Authorization Server prompts the End-User for re-authentication and consent.
        if (!parameters.TryGetValue(RequestParameters.Prompt, out var promptValues) || promptValues.Count == 0)
        {
            return Task.FromResult(PromptValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (promptValues.Count != 1)
        {
            return Task.FromResult(PromptValidationResult.MultiplePrompt);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var prompt = promptValues.ToString();
        if (string.IsNullOrEmpty(prompt))
        {
            // if prompt provided - it must contain valid value, otherwise it shouldn't be included in request
            return Task.FromResult(PromptValidationResult.Null);
        }

        // Space delimited, case sensitive list of ASCII string values
        var requestedPrompts = prompt
            .Split(' ')
            .ToHashSet(StringComparer.Ordinal);
        // syntax validation
        foreach (var requestedPrompt in requestedPrompts)
        {
            if (string.IsNullOrWhiteSpace(requestedPrompt) || (prompt != Prompt.None && prompt != Prompt.Login && prompt != Prompt.Consent && prompt != Prompt.SelectAccount))
            {
                return Task.FromResult(PromptValidationResult.UnsupportedPrompt);
            }
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // If this parameter contains "none" with any other value, an error is returned.
        if (requestedPrompts.Contains(Prompt.None) && requestedPrompts.Count > 1)
        {
            return Task.FromResult(PromptValidationResult.UnsupportedPrompt);
        }

        return Task.FromResult(new PromptValidationResult(requestedPrompts));
    }

    protected virtual Task<MaxAgeValidationResult> ValidateMaxAgeAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "max_age" - OPTIONAL. Maximum Authentication Age.
        // Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP.
        // If the elapsed time is greater than this value, the OP MUST attempt to actively re-authenticate the End-User.
        // When max_age is used, the ID Token returned MUST include an auth_time Claim Value.
        if (!parameters.TryGetValue(RequestParameters.MaxAge, out var maxAgeValues) || maxAgeValues.Count == 0)
        {
            return Task.FromResult(MaxAgeValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (maxAgeValues.Count != 1)
        {
            return Task.FromResult(MaxAgeValidationResult.MultipleMaxAge);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var maxAgeString = maxAgeValues.ToString();
        if (string.IsNullOrEmpty(maxAgeString))
        {
            return Task.FromResult(MaxAgeValidationResult.Null);
        }

        // Integer64 value greater than or equal to zero in seconds.
        if (long.TryParse(maxAgeString, NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxAge) && maxAge >= 0)
        {
            return Task.FromResult(new MaxAgeValidationResult(maxAge));
        }

        return Task.FromResult(MaxAgeValidationResult.InvalidMaxAge);
    }

    protected virtual Task<LoginHintValidationResult> ValidateLoginHintAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "login_hint" - OPTIONAL. Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary).
        // This hint can be used by an RP if it first asks the End-User for their e-mail address (or other identifier) and then wants to pass that value as a hint to the discovered authorization service.
        // It is RECOMMENDED that the hint value match the value used for discovery.
        // This value MAY also be a phone number in the format specified for the "phone_number" Claim. The use of this parameter is left to the OP's discretion.
        if (!parameters.TryGetValue(RequestParameters.LoginHint, out var loginHintValues) || loginHintValues.Count == 0)
        {
            return Task.FromResult(LoginHintValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (loginHintValues.Count != 1)
        {
            return Task.FromResult(LoginHintValidationResult.MultipleLoginHint);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var loginHint = loginHintValues.ToString();
        if (string.IsNullOrEmpty(loginHint))
        {
            return Task.FromResult(LoginHintValidationResult.Null);
        }

        // length check
        if (loginHint.Length > FrameworkOptions.InputLengthRestrictions.LoginHint)
        {
            return Task.FromResult(LoginHintValidationResult.LoginHintIsTooLong);
        }

        return Task.FromResult(new LoginHintValidationResult(loginHint));
    }

    protected virtual Task<AcrValuesValidationResult> ValidateAcrValuesAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(parameters);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "acr_values" - OPTIONAL. Requested Authentication Context Class Reference values.
        // Space-separated string that specifies the acr values that the Authorization Server is being requested to use for processing this Authentication Request, with the values appearing in order of preference.
        // The Authentication Context Class satisfied by the authentication performed is returned as the "acr" Claim Value, as specified in Section 2.
        // The "acr" Claim is requested as a Voluntary Claim by this parameter.
        if (!parameters.TryGetValue(RequestParameters.AcrValues, out var acrValuesValues) || acrValuesValues.Count == 0)
        {
            return Task.FromResult(AcrValuesValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (acrValuesValues.Count != 1)
        {
            return Task.FromResult(AcrValuesValidationResult.MultipleAcrValuesValues);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var acrValues = acrValuesValues.ToString();
        if (string.IsNullOrEmpty(acrValues))
        {
            return Task.FromResult(AcrValuesValidationResult.Null);
        }

        // length check
        if (acrValues.Length > FrameworkOptions.InputLengthRestrictions.AcrValues)
        {
            return Task.FromResult(AcrValuesValidationResult.AcrValuesIsTooLong);
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // Space-separated string with the values appearing in order of preference.
        var requestedAcrValues = acrValues.Split(' ');
        foreach (var requestedAcrValue in requestedAcrValues)
        {
            if (string.IsNullOrEmpty(requestedAcrValue))
            {
                return Task.FromResult(AcrValuesValidationResult.InvalidAcrValuesSyntax);
            }
        }

        return Task.FromResult(new AcrValuesValidationResult(requestedAcrValues));
    }

    protected virtual Task<DisplayValidationResult> ValidateDisplayAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // display - OPTIONAL. ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
        if (!parameters.TryGetValue(RequestParameters.Display, out var displayValues) || displayValues.Count == 0)
        {
            return Task.FromResult(DisplayValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (displayValues.Count != 1)
        {
            return Task.FromResult(DisplayValidationResult.MultipleDisplayValues);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var display = displayValues.ToString();
        if (string.IsNullOrEmpty(display))
        {
            return Task.FromResult(DisplayValidationResult.Null);
        }

        if (display == Display.Page)
        {
            return Task.FromResult(DisplayValidationResult.Page);
        }

        if (display == Display.Popup)
        {
            return Task.FromResult(DisplayValidationResult.Popup);
        }

        if (display == Display.Touch)
        {
            return Task.FromResult(DisplayValidationResult.Touch);
        }

        if (display == Display.Wap)
        {
            return Task.FromResult(DisplayValidationResult.Wap);
        }

        return Task.FromResult(DisplayValidationResult.UnsupportedDisplay);
    }

    protected virtual Task<UiLocalesValidationResult> ValidateUiLocalesAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "ui_locales" - OPTIONAL. End-User's preferred languages and scripts for the user interface,
        // represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference.
        // For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada,
        // then French (without a region designation), followed by English (without a region designation).
        // An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider.
        if (!parameters.TryGetValue(RequestParameters.UiLocales, out var uiLocaleValues) || uiLocaleValues.Count == 0)
        {
            return Task.FromResult(UiLocalesValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (uiLocaleValues.Count != 1)
        {
            return Task.FromResult(UiLocalesValidationResult.MultipleUiLocalesValues);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var uiLocales = uiLocaleValues.ToString();
        if (string.IsNullOrEmpty(uiLocales))
        {
            return Task.FromResult(UiLocalesValidationResult.Null);
        }

        if (uiLocales.Length > FrameworkOptions.InputLengthRestrictions.UiLocales)
        {
            return Task.FromResult(UiLocalesValidationResult.UiLocalesIsTooLong);
        }

        // TODO: syntax validation for language tags
        return Task.FromResult(new UiLocalesValidationResult(uiLocales));
    }

    protected virtual RequestValidationResult ValidateRequest(IReadOnlyDictionary<string, StringValues> parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6
        // Support for the request parameter is OPTIONAL.
        // Should an OP not support this parameter and an RP uses it, the OP MUST return the request_not_supported error.
        if (!parameters.TryGetValue(RequestParameters.Request, out var requestValues) || requestValues.Count == 0)
        {
            return RequestValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (requestValues.Count != 1)
        {
            return RequestValidationResult.MultipleRequestValues;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var request = requestValues.ToString();
        if (string.IsNullOrEmpty(request))
        {
            return RequestValidationResult.Null;
        }

        return RequestValidationResult.RequestNotSupported;
    }

    protected virtual RequestUriValidationResult ValidateRequestUri(IReadOnlyDictionary<string, StringValues> parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2
        // Should an OP not support this parameter and an RP uses it, the OP MUST return the request_uri_not_supported error.
        if (!parameters.TryGetValue(RequestParameters.RequestUri, out var requestUriValues) || requestUriValues.Count == 0)
        {
            return RequestUriValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (requestUriValues.Count != 1)
        {
            return RequestUriValidationResult.MultipleRequestUriValues;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var requestUri = requestUriValues.ToString();
        if (string.IsNullOrEmpty(requestUri))
        {
            return RequestUriValidationResult.Null;
        }

        return RequestUriValidationResult.RequestUriNotSupported;
    }

    protected virtual RegistrationValidationResult ValidateRegistration(IReadOnlyDictionary<string, StringValues> parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.6
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.7.2.1
        // registration_not_supported - The OP does not support use of the registration parameter defined in Section 7.2.1.
        if (!parameters.TryGetValue(RequestParameters.Registration, out var registrationValues) || registrationValues.Count == 0)
        {
            return RegistrationValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (registrationValues.Count != 1)
        {
            return RegistrationValidationResult.MultipleRegistrationValues;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var registration = registrationValues.ToString();
        if (string.IsNullOrEmpty(registration))
        {
            return RegistrationValidationResult.Null;
        }

        return RegistrationValidationResult.RegistrationNotSupported;
    }

    #region ValidationResults

    protected class CoreParameters
    {
        public CoreParameters(
            DateTimeOffset requestDate,
            string issuer,
            TClient client,
            string responseType,
            string grantType,
            string? state,
            string responseMode,
            string redirectUri)
        {
            ArgumentNullException.ThrowIfNull(issuer);
            ArgumentNullException.ThrowIfNull(client);
            ArgumentNullException.ThrowIfNull(responseType);
            ArgumentNullException.ThrowIfNull(grantType);
            ArgumentNullException.ThrowIfNull(responseMode);
            ArgumentNullException.ThrowIfNull(redirectUri);
            RequestDate = requestDate;
            Issuer = issuer;
            Client = client;
            ResponseType = responseType;
            GrantType = grantType;
            State = state;
            ResponseMode = responseMode;
            RedirectUri = redirectUri;
        }

        public DateTimeOffset RequestDate { get; }

        public string Issuer { get; }

        public TClient Client { get; }

        public string ResponseType { get; }

        public string GrantType { get; }

        public string? State { get; }

        public string ResponseMode { get; }

        public string RedirectUri { get; }

        [SuppressMessage("ReSharper", "VirtualMemberNeverOverridden.Global")]
        public virtual AuthorizeRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> BuildError(ProtocolError error)
        {
            return new(new AuthorizeRequestValidationError<TClient, TClientSecret>(RequestDate, Issuer, error, Client, RedirectUri, ResponseMode, State));
        }
    }

    protected class CoreParametersValidationResult
    {
        public CoreParametersValidationResult(ProtocolError error)
        {
            ArgumentNullException.ThrowIfNull(error);
            Error = error;
            HasError = true;
        }

        public CoreParametersValidationResult(CoreParameters value)
        {
            ArgumentNullException.ThrowIfNull(value);
            Value = value;
        }

        public CoreParameters? Value { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(Value))]
        public bool HasError { get; }
    }

    protected class ClientValidationResult
    {
        public static readonly ClientValidationResult ClientIdIsMissing = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"client_id\" is missing"));

        public static readonly ClientValidationResult MultipleClientIdValuesNotAllowed = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"client_id\" values are present, but only one is allowed"));

        public static readonly ClientValidationResult ClientIdIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"client_id\" is too long"));

        public static readonly ClientValidationResult InvalidClientIdSyntax = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"client_id\" syntax"));

        public static readonly ClientValidationResult UnknownOrDisabledClient = new(new ProtocolError(
            Errors.UnauthorizedClient,
            "Unknown or disabled client"));

        public ClientValidationResult(ProtocolError error)
        {
            ArgumentNullException.ThrowIfNull(error);
            Error = error;
            HasError = true;
        }

        public ClientValidationResult(TClient client)
        {
            ArgumentNullException.ThrowIfNull(client);
            Client = client;
        }

        public TClient? Client { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(Client))]
        public bool HasError { get; }
    }

    protected class ResponseTypeValidationResult
    {
        public static readonly ResponseTypeValidationResult Code = new(
            Constants.Requests.Authorize.ResponseType.Code,
            DefaultGrantTypes.AuthorizationCode);

        public static readonly ResponseTypeValidationResult CodeIdToken = new(
            Constants.Requests.Authorize.ResponseType.CodeIdToken,
            DefaultGrantTypes.Hybrid);

        public static readonly ResponseTypeValidationResult ResponseTypeIsMissing = new(new(
            Errors.InvalidRequest,
            "\"response_type\" is missing"));

        public static readonly ResponseTypeValidationResult MultipleResponseTypeValuesNotAllowed = new(new(
            Errors.InvalidRequest,
            "Multiple \"response_type\" values are present, but only one is allowed"));

        public static readonly ResponseTypeValidationResult UnsupportedResponseType = new(new(
            Errors.UnsupportedResponseType,
            "Unsupported \"response_type\""));

        public ResponseTypeValidationResult(ProtocolError error)
        {
            ArgumentNullException.ThrowIfNull(error);
            Error = error;
            HasError = true;
        }

        public ResponseTypeValidationResult(string responseType, string grantType)
        {
            ArgumentNullException.ThrowIfNull(responseType);
            ArgumentNullException.ThrowIfNull(grantType);
            ResponseType = responseType;
            GrantType = grantType;
        }

        public string? ResponseType { get; }

        public string? GrantType { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(ResponseType))]
        [MemberNotNullWhen(false, nameof(GrantType))]
        public bool HasError { get; }
    }

    protected class StateValidationResult
    {
        public static readonly StateValidationResult Null = new((string?) null);

        public static readonly StateValidationResult MultipleStateValuesNotAllowed = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"state\" values are present, but only one is allowed"));

        public static readonly StateValidationResult StateIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"state\" is too long"));

        public static readonly StateValidationResult InvalidStateSyntax = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"state\" syntax"));

        public StateValidationResult(string? state)
        {
            State = state;
        }

        public StateValidationResult(ProtocolError error)
        {
            ArgumentNullException.ThrowIfNull(error);
            Error = error;
            HasError = true;
        }

        public string? State { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class ResponseModeValidationResult
    {
        public static readonly ResponseModeValidationResult Query = new(Constants.Requests.Authorize.ResponseMode.Query);
        public static readonly ResponseModeValidationResult Fragment = new(Constants.Requests.Authorize.ResponseMode.Fragment);
        public static readonly ResponseModeValidationResult FormPost = new(Constants.Requests.Authorize.ResponseMode.FormPost);

        public static readonly ResponseModeValidationResult MultipleResponseModeValuesNotAllowed = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"response_mode\" values are present, but only one is allowed"));

        public static readonly ResponseModeValidationResult UnsupportedResponseMode = new(new ProtocolError(
            Errors.InvalidRequest,
            "Unsupported \"response_mode\""));

        public static readonly ResponseModeValidationResult UnableToInferResponseMode = new(new ProtocolError(
            Errors.InvalidRequest,
            "Unable to infer parameter \"response_mode\""));

        public ResponseModeValidationResult(string responseMode)
        {
            ArgumentNullException.ThrowIfNull(responseMode);
            ResponseMode = responseMode;
        }

        public ResponseModeValidationResult(ProtocolError error)
        {
            ArgumentNullException.ThrowIfNull(error);
            Error = error;
            HasError = true;
        }

        public string? ResponseMode { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(ResponseMode))]
        public bool HasError { get; }
    }

    protected class RedirectUriValidationResult
    {
        public static readonly RedirectUriValidationResult RedirectUriIsMissing = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"redirect_uri\" is missing"));

        public static readonly RedirectUriValidationResult MultipleRedirectUriValuesNotAllowed = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"redirect_uri\" values are present, but only one is allowed"));

        public static readonly RedirectUriValidationResult RedirectUriIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"redirect_uri\" is too long"));

        public static readonly RedirectUriValidationResult InvalidRedirectUriSyntax = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"redirect_uri\" syntax"));

        public static readonly RedirectUriValidationResult InvalidRedirectUri = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"redirect_uri\""));

        public static readonly RedirectUriValidationResult NoPreRegisteredRedirectUrisInClientConfiguration = new(new ProtocolError(
            Errors.ServerError,
            "The client configuration does not contain any pre-registered \"redirect_uri\""));

        public RedirectUriValidationResult(string redirectUri)
        {
            ArgumentNullException.ThrowIfNull(redirectUri);
            RedirectUri = redirectUri;
        }

        public RedirectUriValidationResult(ProtocolError error)
        {
            ArgumentNullException.ThrowIfNull(error);
            Error = error;
            HasError = true;
        }

        public string? RedirectUri { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(RedirectUri))]
        public bool HasError { get; }
    }

    protected class ScopeValidationResult
    {
        public static readonly ScopeValidationResult ScopeIsMissing = new(new ProtocolError(
            Errors.InvalidScope,
            "\"scope\" is missing"));

        public static readonly ScopeValidationResult MultipleScope = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"scope\" values are present, but only 1 has allowed"));

        public static readonly ScopeValidationResult ScopeIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"scope\" parameter is too long"));

        public static readonly ScopeValidationResult InvalidScopeSyntax = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"scope\" syntax"));

        public static readonly ScopeValidationResult InvalidScope = new(new ProtocolError(
            Errors.InvalidScope,
            "Invalid \"scope\""));

        public static readonly ScopeValidationResult Misconfigured = new(new ProtocolError(
            Errors.ServerError,
            "\"scope\" contains misconfigured scopes"));

        public ScopeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ScopeValidationResult(ValidResources<TScope, TResource, TResourceSecret> validResources)
        {
            ValidResources = validResources;
        }

        public ValidResources<TScope, TResource, TResourceSecret>? ValidResources { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(ValidResources))]
        public bool HasError { get; }
    }

    protected class CodeChallengeMethodValidationResult
    {
        public static readonly CodeChallengeMethodValidationResult CodeChallengeMethodIsMissing = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"code_challenge_method\" is missing"));

        public static readonly CodeChallengeMethodValidationResult MultipleCodeChallengeMethod = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"code_challenge_method\" values are present, but only 1 has allowed"));

        public static readonly CodeChallengeMethodValidationResult UnknownCodeChallengeMethod = new(new ProtocolError(
            Errors.InvalidRequest,
            "Unknown \"code_challenge_method\""));

        public static readonly CodeChallengeMethodValidationResult Plain = new(Constants.Requests.Authorize.CodeChallengeMethod.Plain);

        public static readonly CodeChallengeMethodValidationResult S256 = new(Constants.Requests.Authorize.CodeChallengeMethod.S256);

        public CodeChallengeMethodValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public CodeChallengeMethodValidationResult(string codeChallengeMethod)
        {
            CodeChallengeMethod = codeChallengeMethod;
        }

        public string? CodeChallengeMethod { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(CodeChallengeMethod))]
        public bool HasError { get; }
    }

    protected class CodeChallengeValidationResult
    {
        public static readonly CodeChallengeValidationResult CodeChallengeIsMissing = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"code_challenge\" is missing"));

        public static readonly CodeChallengeValidationResult MultipleCodeChallenge = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"code_challenge\" values are present, but only 1 has allowed"));

        public static readonly CodeChallengeValidationResult CodeChallengeIsTooShort = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"code_challenge\" parameter is too short"));

        public static readonly CodeChallengeValidationResult CodeChallengeIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"code_challenge\" parameter is too long"));

        public static readonly CodeChallengeValidationResult InvalidCodeChallengeSyntax = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"code_challenge\" syntax"));

        public CodeChallengeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public CodeChallengeValidationResult(string codeChallenge)
        {
            CodeChallenge = codeChallenge;
        }

        public string? CodeChallenge { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(CodeChallenge))]
        public bool HasError { get; }
    }

    protected class NonceValidationResult
    {
        public static readonly NonceValidationResult Null = new((string?) null);

        public static readonly NonceValidationResult NonceIsMissing = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"nonce\" is missing"));

        public static readonly NonceValidationResult MultipleNonce = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"nonce\" values are present, but only 1 has allowed"));

        public static readonly NonceValidationResult NonceIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"nonce\" parameter is too long"));

        public NonceValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public NonceValidationResult(string? nonce)
        {
            Nonce = nonce;
        }

        public string? Nonce { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class PromptValidationResult
    {
        public static readonly PromptValidationResult Null = new((IReadOnlySet<string>?) null);

        public static readonly PromptValidationResult MultiplePrompt = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"prompt\" parameter values are present, but only 1 has allowed"));

        public static readonly PromptValidationResult UnsupportedPrompt = new(new ProtocolError(
            Errors.InvalidRequest,
            "Provided \"prompt\" is not supported"));

        public PromptValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public PromptValidationResult(IReadOnlySet<string>? prompt)
        {
            Prompt = prompt;
        }

        public IReadOnlySet<string>? Prompt { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class MaxAgeValidationResult
    {
        public static readonly MaxAgeValidationResult Null = new((long?) null);

        public static readonly MaxAgeValidationResult MultipleMaxAge = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"max_age\" parameter values are present, but only 1 has allowed"));

        public static readonly MaxAgeValidationResult InvalidMaxAge = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"max_age\" parameter value"));

        public MaxAgeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public MaxAgeValidationResult(long? maxAge)
        {
            MaxAge = maxAge;
        }

        public long? MaxAge { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class LoginHintValidationResult
    {
        public static readonly LoginHintValidationResult Null = new((string?) null);

        public static readonly LoginHintValidationResult MultipleLoginHint = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"login_hint\" parameter values are present, but only 1 has allowed"));

        public static readonly LoginHintValidationResult LoginHintIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"login_hint\" parameter is too long"));

        public LoginHintValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public LoginHintValidationResult(string? loginHint)
        {
            LoginHint = loginHint;
        }

        public string? LoginHint { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class AcrValuesValidationResult
    {
        public static readonly AcrValuesValidationResult Null = new((string[]?) null);

        public static readonly AcrValuesValidationResult MultipleAcrValuesValues = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"acr_values\" parameter values are present, but only 1 has allowed"));

        public static readonly AcrValuesValidationResult AcrValuesIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"acr_values\" parameter is too long"));

        public static readonly AcrValuesValidationResult InvalidAcrValuesSyntax = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"acr_values\" syntax"));

        public AcrValuesValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public AcrValuesValidationResult(string[]? acrValues)
        {
            AcrValues = acrValues;
        }

        public string[]? AcrValues { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class DisplayValidationResult
    {
        public static readonly DisplayValidationResult Null = new((string?) null);

        public static readonly DisplayValidationResult Page = new(Constants.Requests.Authorize.Display.Page);

        public static readonly DisplayValidationResult Popup = new(Constants.Requests.Authorize.Display.Popup);

        public static readonly DisplayValidationResult Touch = new(Constants.Requests.Authorize.Display.Touch);

        public static readonly DisplayValidationResult Wap = new(Constants.Requests.Authorize.Display.Wap);

        public static readonly DisplayValidationResult MultipleDisplayValues = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"display\" parameter values are present, but only 1 has allowed"));

        public static readonly DisplayValidationResult UnsupportedDisplay = new(new ProtocolError(
            Errors.InvalidRequest,
            "Provided \"display\" is not supported"));

        public DisplayValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public DisplayValidationResult(string? display)
        {
            Display = display;
        }

        public string? Display { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class UiLocalesValidationResult
    {
        public static readonly UiLocalesValidationResult Null = new((string?) null);

        public static readonly UiLocalesValidationResult MultipleUiLocalesValues = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"ui_locales\" parameter values are present, but only 1 has allowed"));

        public static readonly UiLocalesValidationResult UiLocalesIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"ui_locales\" parameter is too long"));

        public UiLocalesValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public UiLocalesValidationResult(string? uiLocales)
        {
            UiLocales = uiLocales;
        }

        public string? UiLocales { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class RequestValidationResult
    {
        public static readonly RequestValidationResult Null = new();

        public static readonly RequestValidationResult MultipleRequestValues = new(new(
            Errors.InvalidRequest,
            "Multiple \"request\" parameter values are present, but only 1 has allowed"));

        public static readonly RequestValidationResult RequestNotSupported = new(new(
            Errors.RequestNotSupported,
            "\"request\" parameter provided but not supported"));

        public RequestValidationResult()
        {
        }

        public RequestValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class RequestUriValidationResult
    {
        public static readonly RequestUriValidationResult Null = new();

        public static readonly RequestUriValidationResult MultipleRequestUriValues = new(new(
            Errors.InvalidRequest,
            "Multiple \"request_uri\" parameter values are present, but only 1 has allowed"));

        public static readonly RequestUriValidationResult RequestUriNotSupported = new(new(
            Errors.RequestUriNotSupported,
            "\"request_uri\" parameter provided but not supported"));

        public RequestUriValidationResult()
        {
        }

        public RequestUriValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    protected class RegistrationValidationResult
    {
        public static readonly RegistrationValidationResult Null = new();

        public static readonly RegistrationValidationResult MultipleRegistrationValues = new(new(
            Errors.InvalidRequest,
            "Multiple \"registration\" parameter values are present, but only 1 has allowed"));

        public static readonly RegistrationValidationResult RegistrationNotSupported = new(new(
            Errors.RegistrationNotSupported,
            "\"registration\" parameter provided but not supported"));

        public RegistrationValidationResult()
        {
        }

        public RegistrationValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    #endregion
}
