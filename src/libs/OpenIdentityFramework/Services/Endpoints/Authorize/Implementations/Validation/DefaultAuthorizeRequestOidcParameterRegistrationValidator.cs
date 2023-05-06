using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants.Request.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;

public class DefaultAuthorizeRequestOidcParameterRegistrationValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestOidcParameterRegistrationValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public virtual Task<AuthorizeRequestOidcParameterRegistrationValidationResult> ValidateRegistrationOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.6
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.7.2.1
        // registration_not_supported - The OP does not support use of the registration parameter defined in Section 7.2.1.
        if (!parameters.Raw.TryGetValue(RequestParameters.Registration, out var registrationValues) || registrationValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterRegistrationValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (registrationValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterRegistrationValidationResult.MultipleRegistrationValues);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var registration = registrationValues.ToString();
        if (string.IsNullOrEmpty(registration))
        {
            return Task.FromResult(AuthorizeRequestOidcParameterRegistrationValidationResult.Null);
        }

        return Task.FromResult(AuthorizeRequestOidcParameterRegistrationValidationResult.RegistrationNotSupported);
    }
}
