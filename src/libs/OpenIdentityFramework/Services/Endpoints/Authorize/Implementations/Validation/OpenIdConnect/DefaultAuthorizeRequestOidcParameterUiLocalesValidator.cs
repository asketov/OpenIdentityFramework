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

public class DefaultAuthorizeRequestOidcParameterUiLocalesValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestOidcParameterUiLocalesValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultAuthorizeRequestOidcParameterUiLocalesValidator(OpenIdentityFrameworkOptions frameworkOptions)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        FrameworkOptions = frameworkOptions;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    public virtual Task<AuthorizeRequestOidcParameterUiLocalesValidationResult> ValidateUiLocalesOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "ui_locales" - OPTIONAL. End-User's preferred languages and scripts for the user interface,
        // represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference.
        // For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada,
        // then French (without a region designation), followed by English (without a region designation).
        // An error SHOULD NOT result if some or all of the requested locales are not supported by the OpenID Provider.
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.UiLocales, out var uiLocaleValues) || uiLocaleValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterUiLocalesValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (uiLocaleValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterUiLocalesValidationResult.MultipleUiLocalesValues);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var uiLocales = uiLocaleValues.ToString();
        if (string.IsNullOrEmpty(uiLocales))
        {
            return Task.FromResult(AuthorizeRequestOidcParameterUiLocalesValidationResult.Null);
        }

        if (uiLocales.Length > FrameworkOptions.InputLengthRestrictions.UiLocales)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterUiLocalesValidationResult.UiLocalesIsTooLong);
        }

        // TODO: syntax validation for language tags
        return Task.FromResult(new AuthorizeRequestOidcParameterUiLocalesValidationResult(uiLocales));
    }
}
