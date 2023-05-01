using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request.Token;
using OpenIdentityFramework.Constants.Response.Token;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenRequestValidator;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations;

public class DefaultTokenRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    : ITokenRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    protected static readonly TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> UnsupportedGrantType =
        new(new ProtocolError(Errors.UnsupportedGrantType, "The authorization grant type is not supported by the authorization server"));

    protected static readonly TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> UnauthorizedClient =
        new(new ProtocolError(Errors.UnauthorizedClient, "The authenticated client is not authorized to use this authorization grant type"));

    protected static readonly TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> InvalidGrant =
        new(new ProtocolError(Errors.InvalidGrant,
            "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirect URI used in the authorization request, or was issued to another client"));

    public DefaultTokenRequestValidator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthorizationCodeService<TClient, TClientSecret, TAuthorizationCode> authorizationCodes,
        ICodeVerifierValidator codeVerifierValidator,
        IResourceValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret> resourceValidator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(authorizationCodes);
        ArgumentNullException.ThrowIfNull(codeVerifierValidator);
        ArgumentNullException.ThrowIfNull(resourceValidator);
        FrameworkOptions = frameworkOptions;
        AuthorizationCodes = authorizationCodes;
        CodeVerifierValidator = codeVerifierValidator;
        ResourceValidator = resourceValidator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    protected IAuthorizationCodeService<TClient, TClientSecret, TAuthorizationCode> AuthorizationCodes { get; }

    protected ICodeVerifierValidator CodeVerifierValidator { get; }

    protected IResourceValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret> ResourceValidator { get; }

    public virtual async Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>> ValidateAsync(
        HttpContext httpContext,
        IFormCollection form,
        TClient client,
        string issuer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var grantTypeValidation = await ValidateGrantTypeAsync(httpContext, form, client, cancellationToken);
        if (grantTypeValidation.HasError)
        {
            return new(grantTypeValidation.Error);
        }

        if (grantTypeValidation.GrantType == DefaultGrantTypes.AuthorizationCode)
        {
            return await ValidateAuthorizationCodeFlowAsync(httpContext, form, client, issuer, cancellationToken);
        }

        return UnsupportedGrantType;
    }

    protected virtual Task<GrantTypeValidationResult> ValidateGrantTypeAsync(
        HttpContext httpContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.1
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2
        // grant_type - REQUIRED. Identifier of the grant type the client uses with the particular token request.
        // This specification defines the values "authorization_code", "refresh_token", and "client_credentials".
        if (!form.TryGetValue(RequestParameters.GrantType, out var grantTypeValues) || grantTypeValues.Count == 0)
        {
            return Task.FromResult(GrantTypeValidationResult.GrantTypeIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (grantTypeValues.Count != 1)
        {
            return Task.FromResult(GrantTypeValidationResult.MultipleGrantTypeValuesNotAllowed);
        }

        var grantType = grantTypeValues.ToString();
        if (grantType == DefaultGrantTypes.AuthorizationCode)
        {
            return Task.FromResult(GrantTypeValidationResult.AuthorizationCode);
        }

        if (grantType == DefaultGrantTypes.ClientCredentials)
        {
            return Task.FromResult(GrantTypeValidationResult.ClientCredentials);
        }

        if (grantType == DefaultGrantTypes.RefreshToken)
        {
            return Task.FromResult(GrantTypeValidationResult.RefreshToken);
        }

        return Task.FromResult(GrantTypeValidationResult.UnsupportedGrant);
    }

    protected virtual async Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>> ValidateAuthorizationCodeFlowAsync(
        HttpContext httpContext,
        IFormCollection form,
        TClient client,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        var clientAuthorizationFlows = client.GetAllowedAuthorizationFlows();
        if (!clientAuthorizationFlows.Contains(DefaultAuthorizationFlows.AuthorizationCode)
            && !clientAuthorizationFlows.Contains(DefaultAuthorizationFlows.Hybrid))
        {
            return UnauthorizedClient;
        }

        var authorizationCodeValidation = await ValidateAuthorizationCodeAsync(httpContext, form, client, cancellationToken);
        if (authorizationCodeValidation.HasError)
        {
            return new(authorizationCodeValidation.Error);
        }

        var authorizationCode = authorizationCodeValidation.AuthorizationCode;
        if (!string.Equals(authorizationCode.GetClientId(), client.GetClientId(), StringComparison.Ordinal))
        {
            return InvalidGrant;
        }

        var codeVerifierValidation = await ValidateCodeVerifierAsync(httpContext, form, client, authorizationCode, cancellationToken);
        if (codeVerifierValidation.HasError)
        {
            return new(codeVerifierValidation.Error);
        }

        var redirectUriValidation = await ValidateAuthorizationCodeRedirectUriAsync(httpContext, form, client, authorizationCode, cancellationToken);
        if (redirectUriValidation.HasError)
        {
            return new(redirectUriValidation.Error);
        }

        var scopeValidation = await ValidateScopeAsync(httpContext, form, client, authorizationCode, cancellationToken);
        if (scopeValidation.HasError)
        {
            return new(scopeValidation.Error);
        }

        return new(new ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>(
            client,
            scopeValidation.ValidResources,
            authorizationCodeValidation.Code,
            authorizationCode,
            issuer));
    }

    protected virtual async Task<AuthorizationCodeValidationResult> ValidateAuthorizationCodeAsync(
        HttpContext httpContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.1
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.3
        // code - REQUIRED. The authorization code received from the authorization server.
        if (!form.TryGetValue(RequestParameters.Code, out var codeValues))
        {
            return AuthorizationCodeValidationResult.AuthorizationCodeIsMissing;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeValues.Count != 1)
        {
            return AuthorizationCodeValidationResult.MultipleAuthorizationCodeValuesNotAllowed;
        }

        var code = codeValues.ToString();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (string.IsNullOrEmpty(code))
        {
            return AuthorizationCodeValidationResult.AuthorizationCodeIsMissing;
        }

        if (code.Length > FrameworkOptions.InputLengthRestrictions.Code)
        {
            return AuthorizationCodeValidationResult.AuthorizationCodeIsTooLong;
        }

        if (!CodeSyntaxValidator.IsValid(code))
        {
            return AuthorizationCodeValidationResult.InvalidAuthorizationCodeSyntax;
        }

        var authorizationCode = await AuthorizationCodes.FindAsync(httpContext, code, cancellationToken);
        if (authorizationCode == null)
        {
            return AuthorizationCodeValidationResult.UnknownCode;
        }

        return new(code, authorizationCode);
    }

    protected virtual Task<CodeVerifierValidationResult> ValidateCodeVerifierAsync(
        HttpContext httpContext,
        IFormCollection form,
        TClient client,
        TAuthorizationCode authorizationCode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(authorizationCode);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.1
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.3
        // code_verifier - REQUIRED, if the code_challenge parameter was included in the authorization request. MUST NOT be used otherwise. The original code verifier string.
        if (!form.TryGetValue(RequestParameters.CodeVerifier, out var codeVerifierValues))
        {
            return Task.FromResult(CodeVerifierValidationResult.CodeVerifierIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeVerifierValues.Count != 1)
        {
            return Task.FromResult(CodeVerifierValidationResult.MultipleCodeVerifierValuesNotAllowed);
        }

        var codeVerifier = codeVerifierValues.ToString();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (string.IsNullOrEmpty(codeVerifier))
        {
            return Task.FromResult(CodeVerifierValidationResult.CodeVerifierIsMissing);
        }

        if (codeVerifier.Length < FrameworkOptions.InputLengthRestrictions.CodeVerifierMinLength)
        {
            return Task.FromResult(CodeVerifierValidationResult.CodeVerifierIsTooShort);
        }

        if (codeVerifier.Length > FrameworkOptions.InputLengthRestrictions.CodeVerifierMaxLength)
        {
            return Task.FromResult(CodeVerifierValidationResult.CodeVerifierIsTooLong);
        }

        if (!CodeVerifierSyntaxValidator.IsValid(codeVerifier))
        {
            return Task.FromResult(CodeVerifierValidationResult.InvalidCodeVerifierSyntax);
        }

        var codeChallenge = authorizationCode.GetCodeChallenge();
        var codeChallengeMethod = authorizationCode.GetCodeChallengeMethod();
        if (!CodeVerifierValidator.IsValid(codeChallenge, codeChallengeMethod, codeVerifier))
        {
            return Task.FromResult(CodeVerifierValidationResult.InvalidCodeVerifier);
        }

        return Task.FromResult(new CodeVerifierValidationResult(codeVerifier));
    }


    protected virtual Task<RedirectUriValidationResult> ValidateAuthorizationCodeRedirectUriAsync(
        HttpContext httpContext,
        IFormCollection form,
        TClient client,
        TAuthorizationCode authorizationCode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(authorizationCode);
        cancellationToken.ThrowIfCancellationRequested();
        var originalRedirectUri = authorizationCode.GetOriginalRedirectUri();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.3
        // "redirect_uri" - REQUIRED, if the redirect_uri parameter was included in the authorization request as described in Section 4.1.1,
        // in which case their values MUST be identical. If no redirect_uri was included in the authorization request, this parameter is OPTIONAL.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.2
        // If the redirect_uri parameter value is not present when there is only one registered redirect_uri value,
        // the Authorization Server MAY return an error (since the Client should have included the parameter)
        // or MAY proceed without an error (since OAuth 2.0 permits the parameter to be omitted in this case).
        if (!form.TryGetValue(RequestParameters.RedirectUri, out var redirectUriValues) || redirectUriValues.Count == 0)
        {
            return Task.FromResult(HandleEmptyTokenRequestParameter(originalRedirectUri));
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
            return Task.FromResult(HandleEmptyTokenRequestParameter(originalRedirectUri));
        }

        // length check
        if (redirectUriString.Length > FrameworkOptions.InputLengthRestrictions.RedirectUri)
        {
            return Task.FromResult(RedirectUriValidationResult.RedirectUriIsTooLong);
        }

        if (string.Equals(redirectUriString, originalRedirectUri, StringComparison.Ordinal))
        {
            return Task.FromResult(new RedirectUriValidationResult(redirectUriString));
        }

        return Task.FromResult(RedirectUriValidationResult.InvalidRedirectUri);


        static RedirectUriValidationResult HandleEmptyTokenRequestParameter(string? originalRedirectUri)
        {
            if (originalRedirectUri is null)
            {
                return RedirectUriValidationResult.Null;
            }

            return RedirectUriValidationResult.RedirectUriIsMissing;
        }
    }

    protected virtual async Task<ScopeValidationResult> ValidateScopeAsync(
        HttpContext httpContext,
        IFormCollection form,
        TClient client,
        TAuthorizationCode authorizationCode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(authorizationCode);
        cancellationToken.ThrowIfCancellationRequested();
        var grantedScopes = authorizationCode.GetGrantedScopes();
        string scopeParameterValue;
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // The authorization and token endpoints allow the client to specify the scope of the access request using the scope request parameter.
        // In turn, the authorization server uses the scope response parameter to inform the client of the scope of the access token issued.
        if (!form.TryGetValue(RequestParameters.Scope, out var scopeValues)
            || scopeValues.Count == 0
            || string.IsNullOrEmpty(scopeParameterValue = scopeValues.ToString()))
        {
            scopeParameterValue = string.Join(' ', grantedScopes);
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

        if (!grantedScopes.IsSupersetOf(requestedScopes))
        {
            return ScopeValidationResult.InvalidScope;
        }

        var allowedTokenTypes = DefaultTokenTypes.OAuth;
        if (requestedScopes.Contains(DefaultScopes.OpenId))
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

    protected class GrantTypeValidationResult
    {
        public static readonly GrantTypeValidationResult GrantTypeIsMissing = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"grant_type\" is missing"));

        public static readonly GrantTypeValidationResult MultipleGrantTypeValuesNotAllowed = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"grant_type\" values are present, but only 1 has allowed"));

        public static readonly GrantTypeValidationResult UnsupportedGrant = new(new ProtocolError(
            Errors.UnsupportedGrantType,
            "Unsupported \"grant_type\""));

        public static readonly GrantTypeValidationResult AuthorizationCode = new(DefaultGrantTypes.AuthorizationCode);
        public static readonly GrantTypeValidationResult ClientCredentials = new(DefaultGrantTypes.ClientCredentials);
        public static readonly GrantTypeValidationResult RefreshToken = new(DefaultGrantTypes.RefreshToken);

        public GrantTypeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public GrantTypeValidationResult(string grantType)
        {
            GrantType = grantType;
            HasError = false;
        }

        public string? GrantType { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(GrantType))]
        public bool HasError { get; }
    }

    protected class CodeVerifierValidationResult
    {
        public static readonly CodeVerifierValidationResult CodeVerifierIsMissing = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"code_verifier\" is missing"));

        public static readonly CodeVerifierValidationResult MultipleCodeVerifierValuesNotAllowed = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"code_verifier\" values are present, but only 1 has allowed"));

        public static readonly CodeVerifierValidationResult CodeVerifierIsTooShort = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"code_verifier\" parameter is too short"));

        public static readonly CodeVerifierValidationResult CodeVerifierIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"code_verifier\" parameter is too long"));

        public static readonly CodeVerifierValidationResult InvalidCodeVerifierSyntax = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"code_verifier\" syntax"));

        public static readonly CodeVerifierValidationResult InvalidCodeVerifier = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"code_verifier\""));

        public CodeVerifierValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public CodeVerifierValidationResult(string codeVerifier)
        {
            CodeVerifier = codeVerifier;
            HasError = false;
        }

        public string? CodeVerifier { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(CodeVerifier))]
        public bool HasError { get; }
    }

    protected class AuthorizationCodeValidationResult
    {
        public static readonly AuthorizationCodeValidationResult AuthorizationCodeIsMissing = new(new(
            Errors.InvalidRequest,
            "\"code\" is missing"));

        public static readonly AuthorizationCodeValidationResult MultipleAuthorizationCodeValuesNotAllowed = new(new(
            Errors.InvalidRequest,
            "Multiple \"code\" values are present, but only 1 has allowed"));

        public static readonly AuthorizationCodeValidationResult AuthorizationCodeIsTooLong = new(new(
            Errors.InvalidRequest,
            "\"code\" is too long"));

        public static readonly AuthorizationCodeValidationResult InvalidAuthorizationCodeSyntax = new(new(
            Errors.InvalidRequest,
            "Invalid \"code\" syntax"));

        public static readonly AuthorizationCodeValidationResult UnknownCode = new(new(
            Errors.InvalidGrant,
            "Unknown \"code\""));

        public AuthorizationCodeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public AuthorizationCodeValidationResult(string code, TAuthorizationCode authorizationCode)
        {
            ArgumentNullException.ThrowIfNull(code);
            ArgumentNullException.ThrowIfNull(authorizationCode);
            Code = code;
            AuthorizationCode = authorizationCode;
            HasError = false;
        }

        public string? Code { get; }
        public TAuthorizationCode? AuthorizationCode { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(Code))]
        [MemberNotNullWhen(false, nameof(AuthorizationCode))]
        public bool HasError { get; }
    }

    protected class RedirectUriValidationResult
    {
        public static readonly RedirectUriValidationResult Null = new((string?) null);

        public static readonly RedirectUriValidationResult RedirectUriIsMissing = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"redirect_uri\" is missing"));

        public static readonly RedirectUriValidationResult MultipleRedirectUriValuesNotAllowed = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"redirect_uri\" values are present, but only one is allowed"));

        public static readonly RedirectUriValidationResult RedirectUriIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"redirect_uri\" is too long"));

        public static readonly RedirectUriValidationResult InvalidRedirectUri = new(new ProtocolError(
            Errors.InvalidRequest,
            "Invalid \"redirect_uri\""));

        public RedirectUriValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public RedirectUriValidationResult(string? originalRedirectUri)
        {
            OriginalRedirectUri = originalRedirectUri;
            HasError = false;
        }

        public string? OriginalRedirectUri { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(OriginalRedirectUri))]
        public bool HasError { get; }
    }

    protected class ScopeValidationResult
    {
        public static readonly ScopeValidationResult MultipleScope = new(new ProtocolError(
            Errors.InvalidRequest,
            "Multiple \"scope\" values are present, but only 1 has allowed"));

        public static readonly ScopeValidationResult ScopeIsTooLong = new(new ProtocolError(
            Errors.InvalidRequest,
            "\"scope\" parameter is too long"));

        public static readonly ScopeValidationResult InvalidScopeSyntax = new(new ProtocolError(
            Errors.InvalidScope,
            "Invalid \"scope\" syntax"));

        public static readonly ScopeValidationResult InvalidScope = new(new ProtocolError(
            Errors.InvalidScope,
            "Invalid \"scope\""));

        public static readonly ScopeValidationResult Misconfigured = new(new ProtocolError(
            Errors.InvalidScope,
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
}
