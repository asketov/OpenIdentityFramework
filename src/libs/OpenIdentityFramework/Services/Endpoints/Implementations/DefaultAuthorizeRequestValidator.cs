using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Implementations;

public class DefaultAuthorizeRequestValidator<TClient> : IAuthorizeRequestValidator
    where TClient : AbstractClient
{
    public DefaultAuthorizeRequestValidator(OpenIdentityFrameworkOptions frameworkOptions, IClientService<TClient> clients)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(clients);
        FrameworkOptions = frameworkOptions;
        Clients = clients;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IClientService<TClient> Clients { get; }

    public virtual async Task<AuthorizeRequestValidationResult> ValidateAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset requestDate,
        string issuer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var isOpenIdRequest = await IsOpenIdConnectRequestAsync(httpContext, parameters, cancellationToken);
        var clientValidation = await ValidateClientAsync(httpContext, parameters, cancellationToken);
        if (clientValidation.HasError)
        {
            throw new NotImplementedException();
        }

        var responseTypeValidation = await ValidateResponseTypeAsync(httpContext, parameters, clientValidation.Client, isOpenIdRequest, cancellationToken);
        if (responseTypeValidation.HasError)
        {
            throw new NotImplementedException();
        }

        var stateValidation = await ValidateStateAsync(httpContext, parameters, cancellationToken);
        if (stateValidation.HasError)
        {
            throw new NotImplementedException();
        }

        var responseModeValidation = await ValidateResponseModeAsync(httpContext, parameters, responseTypeValidation.ResponseType, cancellationToken);
        if (responseModeValidation.HasError)
        {
            throw new NotImplementedException();
        }

        var redirectUri = ValidateRedirectUri(httpContext, parameters, clientValidation.Client, isOpenIdRequest, cancellationToken);
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
        var client = await Clients.FindEnabledAsync(httpContext, clientId, cancellationToken);
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

        var allowedResponseTypes = client.GetAllowedResponseTypes();

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
            var hybridFlowResponseTypes = ResponseType.CodeIdToken.Split(' ').ToHashSet();
            if (multipleResponseTypes.Except(hybridFlowResponseTypes).Any())
            {
                return Task.FromResult(ResponseTypeValidationResult.UnsupportedResponseType);
            }

            return Task.FromResult(ResponseTypeValidationResult.CodeIdToken);
        }

        // Both OAuth 2.1 and OpenID Connect 1.0
        if (responseType == ResponseType.Code && allowedResponseTypes.Contains(ResponseType.Code))
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
            if (ResponseMode.ResponseTypeToResponseMode.TryGetValue(responseType, out var inferredResponseMode))
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

    protected RedirectUriValidationResult ValidateRedirectUri(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client,
        bool isOpenIdRequest,
        CancellationToken cancellationToken)
    {
    }


    #region ValidationResults

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
        public static readonly ResponseTypeValidationResult Code = new(Constants.Requests.Authorize.ResponseType.Code);
        public static readonly ResponseTypeValidationResult CodeIdToken = new(Constants.Requests.Authorize.ResponseType.CodeIdToken);

        public static readonly ResponseTypeValidationResult ResponseTypeIsMissing = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"response_type\" is missing"));

        public static readonly ResponseTypeValidationResult MultipleResponseTypeValuesNotAllowed = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"response_type\" values are present, but only one is allowed"));

        public static readonly ResponseTypeValidationResult UnsupportedResponseType = new(new ProtocolError(
            Errors.UnsupportedResponseType,
            "Unsupported \"response_type\""));

        public ResponseTypeValidationResult(ProtocolError error)
        {
            ArgumentNullException.ThrowIfNull(error);
            Error = error;
            HasError = true;
        }

        public ResponseTypeValidationResult(string responseType)
        {
            ArgumentNullException.ThrowIfNull(responseType);
            ResponseType = responseType;
        }

        public string? ResponseType { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(ResponseType))]
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

    #endregion
}
