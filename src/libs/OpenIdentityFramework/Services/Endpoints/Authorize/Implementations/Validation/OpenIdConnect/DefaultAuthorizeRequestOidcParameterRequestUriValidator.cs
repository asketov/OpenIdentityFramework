using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation.OpenIdConnect;

public class DefaultAuthorizeRequestOidcParameterRequestUriValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestOidcParameterRequestUriValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    public virtual Task<AuthorizeRequestOidcParameterRequestUriValidationResult> ValidateRequestUriOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2
        // Should an OP not support this parameter and an RP uses it, the OP MUST return the request_uri_not_supported error.
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.RequestUri, out var requestUriValues) || requestUriValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterRequestUriValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (requestUriValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterRequestUriValidationResult.MultipleRequestUriValues);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var requestUri = requestUriValues.ToString();
        if (string.IsNullOrEmpty(requestUri))
        {
            return Task.FromResult(AuthorizeRequestOidcParameterRequestUriValidationResult.Null);
        }

        return Task.FromResult(AuthorizeRequestOidcParameterRequestUriValidationResult.RequestUriNotSupported);
    }
}
