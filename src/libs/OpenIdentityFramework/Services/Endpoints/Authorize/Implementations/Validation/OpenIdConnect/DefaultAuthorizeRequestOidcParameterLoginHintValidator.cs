using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation.OpenIdConnect;

public class DefaultAuthorizeRequestOidcParameterLoginHintValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestOidcParameterLoginHintValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultAuthorizeRequestOidcParameterLoginHintValidator(OpenIdentityFrameworkOptions frameworkOptions)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        FrameworkOptions = frameworkOptions;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    public virtual Task<AuthorizeRequestOidcParameterLoginHintValidationResult> ValidateLoginHintOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "login_hint" - OPTIONAL. Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary).
        // This hint can be used by an RP if it first asks the End-User for their e-mail address (or other identifier) and then wants to pass that value as a hint to the discovered authorization service.
        // It is RECOMMENDED that the hint value match the value used for discovery.
        // This value MAY also be a phone number in the format specified for the "phone_number" Claim. The use of this parameter is left to the OP's discretion.
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.LoginHint, out var loginHintValues) || loginHintValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterLoginHintValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (loginHintValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterLoginHintValidationResult.MultipleLoginHint);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var loginHint = loginHintValues.ToString();
        if (string.IsNullOrEmpty(loginHint))
        {
            return Task.FromResult(AuthorizeRequestOidcParameterLoginHintValidationResult.Null);
        }

        // length check
        if (loginHint.Length > FrameworkOptions.InputLengthRestrictions.LoginHint)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterLoginHintValidationResult.LoginHintIsTooLong);
        }

        return Task.FromResult(new AuthorizeRequestOidcParameterLoginHintValidationResult(loginHint));
    }
}
