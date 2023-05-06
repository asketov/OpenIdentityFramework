using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation.OpenIdConnect;

public class DefaultAuthorizeRequestOidcParameterNonceValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestOidcParameterNonceValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultAuthorizeRequestOidcParameterNonceValidator(OpenIdentityFrameworkOptions frameworkOptions)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        FrameworkOptions = frameworkOptions;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    public Task<AuthorizeRequestOidcParameterNonceValidationResult> ValidateNonceOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        string authorizationFlow,
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
        if (!parameters.Raw.TryGetValue(RequestParameters.Nonce, out var nonceValues) || nonceValues.Count == 0)
        {
            return Task.FromResult(InferDefaultResult(authorizationFlow));
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (nonceValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterNonceValidationResult.MultipleNonce);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var nonce = nonceValues.ToString();
        if (string.IsNullOrEmpty(nonce))
        {
            return Task.FromResult(InferDefaultResult(authorizationFlow));
        }

        // length check
        if (nonce.Length > FrameworkOptions.InputLengthRestrictions.Nonce)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterNonceValidationResult.NonceIsTooLong);
        }

        return Task.FromResult(new AuthorizeRequestOidcParameterNonceValidationResult(nonce));
    }

    protected static AuthorizeRequestOidcParameterNonceValidationResult InferDefaultResult(string authorizationFlow)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11
        // nonce - Use of the "nonce" Claim is REQUIRED for this flow (hybrid).
        if (authorizationFlow == DefaultAuthorizationFlows.Hybrid)
        {
            return AuthorizeRequestOidcParameterNonceValidationResult.NonceIsMissing;
        }

        return AuthorizeRequestOidcParameterNonceValidationResult.Null;
    }
}
