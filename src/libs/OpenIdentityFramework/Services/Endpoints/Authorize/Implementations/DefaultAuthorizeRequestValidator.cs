using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultAuthorizeRequestValidator(
        IAuthorizeRequestParameterClientIdValidator<TRequestContext, TClient, TClientSecret> clientIdValidator,
        IAuthorizeRequestParameterResponseTypeValidator<TRequestContext, TClient, TClientSecret> responseTypeValidator,
        IAuthorizeRequestParameterStateValidator<TRequestContext, TClient, TClientSecret> stateValidator,
        IAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret> responseModeValidator,
        IAuthorizeRequestParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret> redirectUriValidator,
        IAuthorizeRequestParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> scopeValidator,
        IAuthorizeRequestParameterCodeChallengeMethodValidator<TRequestContext, TClient, TClientSecret> codeChallengeMethodValidator,
        IAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret> codeChallengeValidator,
        IAuthorizeRequestOidcParameterNonceValidator<TRequestContext, TClient, TClientSecret> nonceValidator,
        IAuthorizeRequestOidcParameterPromptValidator<TRequestContext, TClient, TClientSecret> promptValidator,
        IAuthorizeRequestOidcParameterMaxAgeValidator<TRequestContext, TClient, TClientSecret> maxAgeValidator,
        IAuthorizeRequestOidcParameterLoginHintValidator<TRequestContext, TClient, TClientSecret> loginHintValidator,
        IAuthorizeRequestOidcParameterAcrValuesValidator<TRequestContext, TClient, TClientSecret> acrValuesValidator,
        IAuthorizeRequestOidcParameterDisplayValidator<TRequestContext, TClient, TClientSecret> displayValidator,
        IAuthorizeRequestOidcParameterUiLocalesValidator<TRequestContext, TClient, TClientSecret> uiLocalesValidator,
        IAuthorizeRequestOidcParameterRequestValidator<TRequestContext, TClient, TClientSecret> requestValidator,
        IAuthorizeRequestOidcParameterRequestUriValidator<TRequestContext, TClient, TClientSecret> requestUriValidator,
        IAuthorizeRequestOidcParameterRegistrationValidator<TRequestContext, TClient, TClientSecret> registrationValidator)
    {
        ArgumentNullException.ThrowIfNull(clientIdValidator);
        ArgumentNullException.ThrowIfNull(responseTypeValidator);
        ArgumentNullException.ThrowIfNull(stateValidator);
        ArgumentNullException.ThrowIfNull(responseModeValidator);
        ArgumentNullException.ThrowIfNull(redirectUriValidator);
        ArgumentNullException.ThrowIfNull(scopeValidator);
        ArgumentNullException.ThrowIfNull(codeChallengeMethodValidator);
        ArgumentNullException.ThrowIfNull(codeChallengeValidator);
        ArgumentNullException.ThrowIfNull(nonceValidator);
        ArgumentNullException.ThrowIfNull(promptValidator);
        ArgumentNullException.ThrowIfNull(maxAgeValidator);
        ArgumentNullException.ThrowIfNull(loginHintValidator);
        ArgumentNullException.ThrowIfNull(acrValuesValidator);
        ArgumentNullException.ThrowIfNull(displayValidator);
        ArgumentNullException.ThrowIfNull(uiLocalesValidator);
        ArgumentNullException.ThrowIfNull(requestValidator);
        ArgumentNullException.ThrowIfNull(requestUriValidator);
        ArgumentNullException.ThrowIfNull(registrationValidator);
        ClientIdValidator = clientIdValidator;
        ResponseTypeValidator = responseTypeValidator;
        StateValidator = stateValidator;
        ResponseModeValidator = responseModeValidator;
        RedirectUriValidator = redirectUriValidator;
        ScopeValidator = scopeValidator;
        CodeChallengeMethodValidator = codeChallengeMethodValidator;
        CodeChallengeValidator = codeChallengeValidator;
        NonceValidator = nonceValidator;
        PromptValidator = promptValidator;
        MaxAgeValidator = maxAgeValidator;
        LoginHintValidator = loginHintValidator;
        AcrValuesValidator = acrValuesValidator;
        DisplayValidator = displayValidator;
        UiLocalesValidator = uiLocalesValidator;
        RequestValidator = requestValidator;
        RequestUriValidator = requestUriValidator;
        RegistrationValidator = registrationValidator;
    }

    protected IAuthorizeRequestParameterClientIdValidator<TRequestContext, TClient, TClientSecret> ClientIdValidator { get; }
    protected IAuthorizeRequestParameterResponseTypeValidator<TRequestContext, TClient, TClientSecret> ResponseTypeValidator { get; }
    protected IAuthorizeRequestParameterStateValidator<TRequestContext, TClient, TClientSecret> StateValidator { get; }
    protected IAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret> ResponseModeValidator { get; }
    protected IAuthorizeRequestParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret> RedirectUriValidator { get; }
    protected IAuthorizeRequestParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ScopeValidator { get; }
    protected IAuthorizeRequestParameterCodeChallengeMethodValidator<TRequestContext, TClient, TClientSecret> CodeChallengeMethodValidator { get; }
    protected IAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret> CodeChallengeValidator { get; }
    protected IAuthorizeRequestOidcParameterNonceValidator<TRequestContext, TClient, TClientSecret> NonceValidator { get; }
    protected IAuthorizeRequestOidcParameterPromptValidator<TRequestContext, TClient, TClientSecret> PromptValidator { get; }
    protected IAuthorizeRequestOidcParameterMaxAgeValidator<TRequestContext, TClient, TClientSecret> MaxAgeValidator { get; }
    protected IAuthorizeRequestOidcParameterLoginHintValidator<TRequestContext, TClient, TClientSecret> LoginHintValidator { get; }
    protected IAuthorizeRequestOidcParameterAcrValuesValidator<TRequestContext, TClient, TClientSecret> AcrValuesValidator { get; }
    protected IAuthorizeRequestOidcParameterDisplayValidator<TRequestContext, TClient, TClientSecret> DisplayValidator { get; }
    protected IAuthorizeRequestOidcParameterUiLocalesValidator<TRequestContext, TClient, TClientSecret> UiLocalesValidator { get; }
    protected IAuthorizeRequestOidcParameterRequestValidator<TRequestContext, TClient, TClientSecret> RequestValidator { get; }
    protected IAuthorizeRequestOidcParameterRequestUriValidator<TRequestContext, TClient, TClientSecret> RequestUriValidator { get; }
    protected IAuthorizeRequestOidcParameterRegistrationValidator<TRequestContext, TClient, TClientSecret> RegistrationValidator { get; }

    public virtual async Task<AuthorizeRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> ValidateAsync(
        TRequestContext requestContext,
        IReadOnlyDictionary<string, StringValues> rawParameters,
        DateTimeOffset initialRequestDate,
        string issuer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var parameters = await GetParametersToValidateAsync(requestContext, rawParameters, cancellationToken);
        var coreParametersValidation = await ValidateCoreParametersAsync(
            requestContext,
            parameters,
            initialRequestDate,
            issuer,
            cancellationToken);
        if (coreParametersValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError<TClient, TClientSecret>(
                initialRequestDate,
                issuer,
                coreParametersValidation.Error));
        }

        var coreParameters = coreParametersValidation.Value;
        var scopeValidation = await ScopeValidator.ValidateScopeParameterAsync(requestContext, parameters, coreParametersValidation.Value.Client, cancellationToken);
        if (scopeValidation.HasError)
        {
            return coreParameters.BuildError(scopeValidation.Error);
        }

        var codeChallengeMethodValidation = await CodeChallengeMethodValidator.ValidateCodeChallengeMethodParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (codeChallengeMethodValidation.HasError)
        {
            return coreParameters.BuildError(codeChallengeMethodValidation.Error);
        }

        var codeChallengeValidation = await CodeChallengeValidator.ValidateCodeChallengeParameterAsync(requestContext, parameters, coreParameters.Client, codeChallengeMethodValidation.CodeChallengeMethod, cancellationToken);
        if (codeChallengeValidation.HasError)
        {
            return coreParameters.BuildError(codeChallengeValidation.Error);
        }

        if (!parameters.IsOpenIdRequest)
        {
            return new(new ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
                initialRequestDate,
                issuer,
                coreParameters.Client,
                coreParameters.RedirectUriToUse,
                coreParameters.AuthorizeRequestRedirectUri,
                scopeValidation.ValidResources,
                codeChallengeValidation.CodeChallenge,
                codeChallengeMethodValidation.CodeChallengeMethod,
                coreParameters.ResponseType,
                coreParameters.AuthorizationFlow,
                coreParameters.State,
                coreParameters.ResponseMode,
                rawParameters));
        }

        var nonceValidation = await NonceValidator.ValidateNonceOidcParameterAsync(requestContext, parameters, coreParameters.Client, coreParameters.AuthorizationFlow, cancellationToken);
        if (nonceValidation.HasError)
        {
            return coreParameters.BuildError(nonceValidation.Error);
        }

        var promptValidation = await PromptValidator.ValidatePromptOidcParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (promptValidation.HasError)
        {
            return coreParameters.BuildError(promptValidation.Error);
        }

        var maxAgeValidation = await MaxAgeValidator.ValidateMaxAgeOidcParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (maxAgeValidation.HasError)
        {
            return coreParameters.BuildError(maxAgeValidation.Error);
        }

        var loginHintValidation = await LoginHintValidator.ValidateLoginHintOidcParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (loginHintValidation.HasError)
        {
            return coreParameters.BuildError(loginHintValidation.Error);
        }

        var acrValuesValidation = await AcrValuesValidator.ValidateAcrValuesOidcParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (acrValuesValidation.HasError)
        {
            return coreParameters.BuildError(acrValuesValidation.Error);
        }

        var displayValidation = await DisplayValidator.ValidateDisplayOidcParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (displayValidation.HasError)
        {
            return coreParameters.BuildError(displayValidation.Error);
        }

        var uiLocalesValidation = await UiLocalesValidator.ValidateUiLocalesOidcParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (uiLocalesValidation.HasError)
        {
            return coreParameters.BuildError(uiLocalesValidation.Error);
        }

        var requestValidation = await RequestValidator.ValidateRequestOidcParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (requestValidation.HasError)
        {
            return coreParameters.BuildError(requestValidation.Error);
        }

        var requestUriValidation = await RequestUriValidator.ValidateRequestUriOidcParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (requestUriValidation.HasError)
        {
            return coreParameters.BuildError(requestUriValidation.Error);
        }

        var registrationValidation = await RegistrationValidator.ValidateRegistrationOidcParameterAsync(requestContext, parameters, coreParameters.Client, cancellationToken);
        if (registrationValidation.HasError)
        {
            return coreParameters.BuildError(registrationValidation.Error);
        }

        return new(new ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            initialRequestDate,
            issuer,
            coreParameters.Client,
            coreParameters.RedirectUriToUse,
            coreParameters.AuthorizeRequestRedirectUri,
            scopeValidation.ValidResources,
            codeChallengeValidation.CodeChallenge,
            codeChallengeMethodValidation.CodeChallengeMethod,
            coreParameters.ResponseType,
            coreParameters.AuthorizationFlow,
            coreParameters.State,
            coreParameters.ResponseMode,
            nonceValidation.Nonce,
            displayValidation.Display,
            promptValidation.Prompt,
            maxAgeValidation.MaxAge,
            uiLocalesValidation.UiLocales,
            loginHintValidation.LoginHint,
            acrValuesValidation.AcrValues,
            rawParameters));
    }

    protected virtual async Task<CoreParametersValidationResult> ValidateCoreParametersAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        DateTimeOffset requestDate,
        string issuer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var clientValidation = await ClientIdValidator.ValidateClientIdParameterAsync(requestContext, parameters, cancellationToken);
        if (clientValidation.HasError)
        {
            return new(clientValidation.Error);
        }

        var responseTypeValidation = await ResponseTypeValidator.ValidateResponseTypeParameterAsync(requestContext, parameters, clientValidation.Client, cancellationToken);
        if (responseTypeValidation.HasError)
        {
            return new(responseTypeValidation.Error);
        }

        var stateValidation = await StateValidator.ValidateStateParameterAsync(requestContext, parameters, clientValidation.Client, cancellationToken);
        if (stateValidation.HasError)
        {
            return new(stateValidation.Error);
        }

        var responseModeValidation = await ResponseModeValidator.ValidateResponseModeParameterAsync(requestContext, parameters, clientValidation.Client, responseTypeValidation.ResponseType, cancellationToken);
        if (responseModeValidation.HasError)
        {
            return new(responseModeValidation.Error);
        }

        var redirectUriValidation = await RedirectUriValidator.ValidateRedirectUriAsync(requestContext, parameters, clientValidation.Client, cancellationToken);
        if (redirectUriValidation.HasError)
        {
            return new(redirectUriValidation.Error);
        }

        return new(new CoreParameters(
            requestDate,
            issuer,
            clientValidation.Client,
            responseTypeValidation.ResponseType,
            responseTypeValidation.AuthorizationFlow,
            stateValidation.State,
            responseModeValidation.ResponseMode,
            redirectUriValidation.RedirectUriToUse,
            redirectUriValidation.AuthorizeRequestRedirectUri));
    }

    protected virtual async Task<AuthorizeRequestParametersToValidate> GetParametersToValidateAsync(
        TRequestContext requestContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var isOpenIdRequest = await IsOpenIdConnectRequestAsync(requestContext, parameters, cancellationToken);
        return new(parameters, isOpenIdRequest);
    }

    protected virtual Task<bool> IsOpenIdConnectRequestAsync(
        TRequestContext requestContext,
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
        if (!parameters.TryGetValue(AuthorizeRequestParameters.Scope, out var scopeValues) || scopeValues.Count == 0)
        {
            return Task.FromResult(false);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (scopeValues.Count > 1)
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

    protected class CoreParameters
    {
        public CoreParameters(
            DateTimeOffset requestDate,
            string issuer,
            TClient client,
            string responseType,
            string authorizationFlow,
            string? state,
            string responseMode,
            string redirectUriToUse,
            string? authorizeRequestRedirectUri)
        {
            ArgumentNullException.ThrowIfNull(issuer);
            ArgumentNullException.ThrowIfNull(client);
            ArgumentNullException.ThrowIfNull(responseType);
            ArgumentNullException.ThrowIfNull(authorizationFlow);
            ArgumentNullException.ThrowIfNull(responseMode);
            ArgumentNullException.ThrowIfNull(redirectUriToUse);
            RequestDate = requestDate;
            Issuer = issuer;
            Client = client;
            ResponseType = responseType;
            AuthorizationFlow = authorizationFlow;
            State = state;
            ResponseMode = responseMode;
            RedirectUriToUse = redirectUriToUse;
            AuthorizeRequestRedirectUri = authorizeRequestRedirectUri;
        }

        public DateTimeOffset RequestDate { get; }

        public string Issuer { get; }

        public TClient Client { get; }

        public string ResponseType { get; }

        public string AuthorizationFlow { get; }

        public string? State { get; }

        public string ResponseMode { get; }

        public string RedirectUriToUse { get; }
        public string? AuthorizeRequestRedirectUri { get; }

        [SuppressMessage("ReSharper", "VirtualMemberNeverOverridden.Global")]
        public virtual AuthorizeRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> BuildError(ProtocolError error)
        {
            return new(new AuthorizeRequestValidationError<TClient, TClientSecret>(RequestDate, Issuer, error, Client, RedirectUriToUse, ResponseMode, State));
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
}
