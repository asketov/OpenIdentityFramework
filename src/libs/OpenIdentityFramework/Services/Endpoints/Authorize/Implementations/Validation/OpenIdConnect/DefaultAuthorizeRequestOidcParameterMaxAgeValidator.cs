using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation.OpenIdConnect;

public class DefaultAuthorizeRequestOidcParameterMaxAgeValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestOidcParameterMaxAgeValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public virtual Task<AuthorizeRequestOidcParameterMaxAgeValidationResult> ValidateMaxAgeOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "max_age" - OPTIONAL. Maximum Authentication Age.
        // Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP.
        // If the elapsed time is greater than this value, the OP MUST attempt to actively re-authenticate the End-User.
        // When max_age is used, the ID Token returned MUST include an auth_time Claim Value.
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.MaxAge, out var maxAgeValues) || maxAgeValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterMaxAgeValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (maxAgeValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterMaxAgeValidationResult.MultipleMaxAge);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var maxAgeString = maxAgeValues.ToString();
        if (string.IsNullOrEmpty(maxAgeString))
        {
            return Task.FromResult(AuthorizeRequestOidcParameterMaxAgeValidationResult.Null);
        }

        // Integer64 value greater than or equal to zero in seconds.
        if (long.TryParse(maxAgeString, NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxAge) && maxAge >= 0)
        {
            return Task.FromResult(new AuthorizeRequestOidcParameterMaxAgeValidationResult(maxAge));
        }

        return Task.FromResult(AuthorizeRequestOidcParameterMaxAgeValidationResult.InvalidMaxAge);
    }
}
