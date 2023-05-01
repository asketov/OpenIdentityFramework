using System;
using System.Collections.Generic;
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

public class DefaultTokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>
    : ITokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
    where TRefreshToken : AbstractRefreshToken
{
    protected static readonly TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> UnsupportedGrantType =
        new(new ProtocolError(Errors.UnsupportedGrantType, "The authorization grant type is not supported by the authorization server"));

    protected static readonly TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> UnauthorizedClient =
        new(new ProtocolError(Errors.UnauthorizedClient, "The authenticated client is not authorized to use this authorization grant type"));

    protected static readonly TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> InvalidGrant =
        new(new ProtocolError(Errors.InvalidGrant,
            "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirect URI used in the authorization request, or was issued to another client"));

    public DefaultTokenRequestValidator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode> authorizationCodes,
        ICodeVerifierValidator codeVerifierValidator,
        IResourceValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> resourceValidator,
        IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> refreshTokens)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(authorizationCodes);
        ArgumentNullException.ThrowIfNull(codeVerifierValidator);
        ArgumentNullException.ThrowIfNull(resourceValidator);
        ArgumentNullException.ThrowIfNull(refreshTokens);
        FrameworkOptions = frameworkOptions;
        AuthorizationCodes = authorizationCodes;
        CodeVerifierValidator = codeVerifierValidator;
        ResourceValidator = resourceValidator;
        RefreshTokens = refreshTokens;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    protected IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode> AuthorizationCodes { get; }

    protected ICodeVerifierValidator CodeVerifierValidator { get; }

    protected IResourceValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ResourceValidator { get; }

    protected IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> RefreshTokens { get; }

    public virtual async Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>> ValidateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        string clientAuthenticationMethod,
        string issuer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var grantTypeValidation = await ValidateGrantTypeAsync(requestContext, form, client, cancellationToken);
        if (grantTypeValidation.HasError)
        {
            return new(grantTypeValidation.Error);
        }

        if (grantTypeValidation.GrantType == DefaultGrantTypes.AuthorizationCode)
        {
            return await ValidateAuthorizationCodeFlowAsync(requestContext, form, client, issuer, cancellationToken);
        }

        if (grantTypeValidation.GrantType == DefaultGrantTypes.ClientCredentials)
        {
            return await ValidateClientCredentialsFlowAsync(requestContext, form, client, clientAuthenticationMethod, issuer, cancellationToken);
        }

        if (grantTypeValidation.GrantType == DefaultGrantTypes.RefreshToken)
        {
            return await ValidateRefreshTokenFlowAsync(requestContext, form, client, issuer, cancellationToken);
        }

        return UnsupportedGrantType;
    }

    protected virtual Task<GrantTypeValidationResult> ValidateGrantTypeAsync(
        TRequestContext requestContext,
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

    protected virtual async Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>> ValidateAuthorizationCodeFlowAsync(
        TRequestContext requestContext,
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

        var authorizationCodeValidation = await ValidateAuthorizationCodeAsync(requestContext, form, client, cancellationToken);
        if (authorizationCodeValidation.HasError)
        {
            return new(authorizationCodeValidation.Error);
        }

        var authorizationCode = authorizationCodeValidation.AuthorizationCode;
        if (!string.Equals(authorizationCode.GetClientId(), client.GetClientId(), StringComparison.Ordinal))
        {
            return InvalidGrant;
        }

        var codeVerifierValidation = await ValidateCodeVerifierAsync(requestContext, form, client, authorizationCode, cancellationToken);
        if (codeVerifierValidation.HasError)
        {
            return new(codeVerifierValidation.Error);
        }

        var redirectUriValidation = await ValidateAuthorizationCodeRedirectUriAsync(requestContext, form, client, authorizationCode, cancellationToken);
        if (redirectUriValidation.HasError)
        {
            return new(redirectUriValidation.Error);
        }

        var scopeValidation = await ValidateScopeAsync(requestContext, form, client, authorizationCode.GetGrantedScopes(), cancellationToken);
        if (scopeValidation.HasError)
        {
            return new(scopeValidation.Error);
        }

        var result = CreateAuthorizationCodeResult(
            client,
            scopeValidation.AllowedResources,
            authorizationCodeValidation.Handle,
            authorizationCodeValidation.AuthorizationCode,
            issuer);
        return new(result);
    }

    protected virtual async Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>> ValidateClientCredentialsFlowAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        string clientAuthenticationMethod,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        if (!client.GetAllowedAuthorizationFlows().Contains(DefaultAuthorizationFlows.ClientCredentials))
        {
            return UnauthorizedClient;
        }

        if (client.GetClientType() is not DefaultClientTypes.Confidential)
        {
            return UnauthorizedClient;
        }

        if (clientAuthenticationMethod == DefaultClientAuthenticationMethods.None)
        {
            return UnauthorizedClient;
        }

        var scopeValidation = await ValidateClientCredentialsScopeAsync(requestContext, form, client, cancellationToken);
        if (scopeValidation.HasError)
        {
            return new(scopeValidation.Error);
        }

        var result = CreateClientCredentialsResult(
            client,
            scopeValidation.AllowedResources,
            issuer);
        return new(result);
    }

    protected virtual async Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>> ValidateRefreshTokenFlowAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        if (!client.GetAllowedAuthorizationFlows().Contains(DefaultAuthorizationFlows.RefreshToken))
        {
            return UnauthorizedClient;
        }

        var refreshTokenValidation = await ValidateRefreshTokenAsync(requestContext, form, client, issuer, cancellationToken);
        if (refreshTokenValidation.HasError)
        {
            return new(refreshTokenValidation.Error);
        }

        var refreshTokenScopes = refreshTokenValidation.RefreshToken.GetGrantedScopes();
        var scopeValidation = await ValidateScopeAsync(requestContext, form, client, refreshTokenScopes, cancellationToken);
        if (scopeValidation.HasError)
        {
            return new(scopeValidation.Error);
        }

        var result = CreateRefreshTokenResult(
            client,
            scopeValidation.AllowedResources,
            refreshTokenValidation.Handle,
            refreshTokenValidation.RefreshToken,
            issuer);
        return new(result);
    }

    protected ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> CreateAuthorizationCodeResult(
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        string handle,
        TAuthorizationCode authorizationCode,
        string issuer)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(allowedResources);
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(authorizationCode);
        ArgumentNullException.ThrowIfNull(issuer);
        return new(
            DefaultGrantTypes.AuthorizationCode,
            client,
            issuer,
            allowedResources,
            authorizationCode,
            null,
            handle,
            null);
    }

    protected ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> CreateClientCredentialsResult(
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        string issuer)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(allowedResources);
        ArgumentNullException.ThrowIfNull(issuer);
        return new(
            DefaultGrantTypes.ClientCredentials,
            client,
            issuer,
            allowedResources,
            null,
            null,
            null,
            null);
    }

    protected ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> CreateRefreshTokenResult(
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> allowedResources,
        string handle,
        TRefreshToken refreshToken,
        string issuer)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(allowedResources);
        ArgumentNullException.ThrowIfNull(issuer);
        return new(
            DefaultGrantTypes.RefreshToken,
            client,
            issuer,
            allowedResources,
            null,
            refreshToken,
            null,
            handle);
    }

    protected virtual async Task<AuthorizationCodeValidationResult> ValidateAuthorizationCodeAsync(
        TRequestContext requestContext,
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

        var authorizationCode = await AuthorizationCodes.FindAsync(requestContext, code, cancellationToken);
        if (authorizationCode == null)
        {
            return AuthorizationCodeValidationResult.UnknownCode;
        }

        return new(code, authorizationCode);
    }

    protected virtual Task<CodeVerifierValidationResult> ValidateCodeVerifierAsync(
        TRequestContext requestContext,
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
        TRequestContext requestContext,
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
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        IReadOnlySet<string> grantedScopes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(grantedScopes);
        cancellationToken.ThrowIfCancellationRequested();
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
        if (scopeValues.Count > 1)
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

        var requestedScopesValidation = await ResourceValidator.ValidateRequestedScopesAsync(requestContext, client, requestedScopes, allowedTokenTypes, cancellationToken);
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

    protected virtual async Task<ScopeValidationResult> ValidateClientCredentialsScopeAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        var defaultScopes = client.GetAllowedScopes();
        string scopeParameterValue;
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.2.1
        // "scope": OPTIONAL. The scope of the access request as described by Section 3.2.2.1.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // The authorization and token endpoints allow the client to specify the scope of the access request using the scope request parameter.
        // In turn, the authorization server uses the scope response parameter to inform the client of the scope of the access token issued.
        if (!form.TryGetValue(RequestParameters.Scope, out var scopeValues)
            || scopeValues.Count == 0
            || string.IsNullOrEmpty(scopeParameterValue = scopeValues.ToString()))
        {
            scopeParameterValue = string.Join(' ', defaultScopes);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (scopeValues.Count > 1)
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

        if (!defaultScopes.IsSupersetOf(requestedScopes))
        {
            return ScopeValidationResult.InvalidScope;
        }

        var requestedScopesValidation = await ResourceValidator.ValidateRequestedScopesAsync(requestContext, client, requestedScopes, DefaultTokenTypes.OAuth, cancellationToken);
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

    protected async Task<RefreshTokenValidationResult> ValidateRefreshTokenAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        string issuer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.3.1
        // "refresh_token" - REQUIRED. The refresh token issued to the client.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.12
        // A request to the Token Endpoint can also use a Refresh Token by using the grant_type value refresh_token, as described in Section 6 of OAuth 2.0 [RFC6749].
        // This section defines the behaviors for OpenID Connect Authorization Servers when Refresh Tokens are used.
        if (!form.TryGetValue(RequestParameters.RefreshToken, out var refreshTokenValues))
        {
            return RefreshTokenValidationResult.RefreshTokenIsMissing;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (refreshTokenValues.Count != 1)
        {
            return RefreshTokenValidationResult.MultipleRefreshTokenValuesNotAllowed;
        }

        var refreshTokenHandle = refreshTokenValues.ToString();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (string.IsNullOrEmpty(refreshTokenHandle))
        {
            return RefreshTokenValidationResult.RefreshTokenIsMissing;
        }

        if (refreshTokenHandle.Length > FrameworkOptions.InputLengthRestrictions.RefreshToken)
        {
            return RefreshTokenValidationResult.RefreshTokenIsTooLong;
        }

        var refreshToken = await RefreshTokens.FindAsync(requestContext, client, issuer, refreshTokenHandle, cancellationToken);
        if (refreshToken is not null)
        {
            return new(refreshTokenHandle, refreshToken);
        }

        return RefreshTokenValidationResult.UnknownRefreshToken;
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

        public AuthorizationCodeValidationResult(string handle, TAuthorizationCode authorizationCode)
        {
            ArgumentNullException.ThrowIfNull(handle);
            ArgumentNullException.ThrowIfNull(authorizationCode);
            Handle = handle;
            AuthorizationCode = authorizationCode;
            HasError = false;
        }

        public string? Handle { get; }
        public TAuthorizationCode? AuthorizationCode { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(Handle))]
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

        public ScopeValidationResult(ValidResources<TScope, TResource, TResourceSecret> allowedResources)
        {
            AllowedResources = allowedResources;
        }

        public ValidResources<TScope, TResource, TResourceSecret>? AllowedResources { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(AllowedResources))]
        public bool HasError { get; }
    }

    protected class RefreshTokenValidationResult
    {
        public static readonly RefreshTokenValidationResult RefreshTokenIsMissing = new(new(
            Errors.InvalidRequest,
            "\"refresh_token\" is missing"));

        public static readonly RefreshTokenValidationResult MultipleRefreshTokenValuesNotAllowed = new(new(
            Errors.InvalidRequest,
            "Multiple \"refresh_token\" values are present, but only 1 has allowed"));

        public static readonly RefreshTokenValidationResult RefreshTokenIsTooLong = new(new(
            Errors.InvalidRequest,
            "\"refresh_token\" is too long"));

        public static readonly RefreshTokenValidationResult UnknownRefreshToken = new(new(
            Errors.InvalidGrant,
            "Unknown \"refresh_token\""));

        public RefreshTokenValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public RefreshTokenValidationResult(string handle, TRefreshToken refreshToken)
        {
            ArgumentNullException.ThrowIfNull(handle);
            ArgumentNullException.ThrowIfNull(refreshToken);
            Handle = handle;
            RefreshToken = refreshToken;
            HasError = false;
        }

        public string? Handle { get; }
        public TRefreshToken? RefreshToken { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(Handle))]
        [MemberNotNullWhen(false, nameof(RefreshToken))]
        public bool HasError { get; }
    }
}
