using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants.Request.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation.OpenIdConnect;

public class DefaultAuthorizeRequestOidcParameterDisplayValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestOidcParameterDisplayValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public Task<AuthorizeRequestOidcParameterDisplayValidationResult> ValidateDisplayOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // display - OPTIONAL. ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
        if (!parameters.Raw.TryGetValue(RequestParameters.Display, out var displayValues) || displayValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterDisplayValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (displayValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterDisplayValidationResult.MultipleDisplayValues);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var display = displayValues.ToString();
        if (string.IsNullOrEmpty(display))
        {
            return Task.FromResult(AuthorizeRequestOidcParameterDisplayValidationResult.Null);
        }

        if (display == Display.Page)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterDisplayValidationResult.Page);
        }

        if (display == Display.Popup)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterDisplayValidationResult.Popup);
        }

        if (display == Display.Touch)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterDisplayValidationResult.Touch);
        }

        if (display == Display.Wap)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterDisplayValidationResult.Wap);
        }

        return Task.FromResult(AuthorizeRequestOidcParameterDisplayValidationResult.UnsupportedDisplay);
    }
}
