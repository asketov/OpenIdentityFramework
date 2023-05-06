using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Request.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation.OpenIdConnect;

public class DefaultAuthorizeRequestOidcParameterAcrValuesValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestOidcParameterAcrValuesValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultAuthorizeRequestOidcParameterAcrValuesValidator(OpenIdentityFrameworkOptions frameworkOptions)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        FrameworkOptions = frameworkOptions;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    public Task<AuthorizeRequestOidcParameterAcrValuesValidationResult> ValidateAcrValuesOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(parameters);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "acr_values" - OPTIONAL. Requested Authentication Context Class Reference values.
        // Space-separated string that specifies the acr values that the Authorization Server is being requested to use for processing this Authentication Request, with the values appearing in order of preference.
        // The Authentication Context Class satisfied by the authentication performed is returned as the "acr" Claim Value, as specified in Section 2.
        // The "acr" Claim is requested as a Voluntary Claim by this parameter.
        if (!parameters.Raw.TryGetValue(RequestParameters.AcrValues, out var acrValuesValues) || acrValuesValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterAcrValuesValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (acrValuesValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterAcrValuesValidationResult.MultipleAcrValuesValues);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var acrValues = acrValuesValues.ToString();
        if (string.IsNullOrEmpty(acrValues))
        {
            return Task.FromResult(AuthorizeRequestOidcParameterAcrValuesValidationResult.Null);
        }

        // length check
        if (acrValues.Length > FrameworkOptions.InputLengthRestrictions.AcrValues)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterAcrValuesValidationResult.AcrValuesIsTooLong);
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // Space-separated string with the values appearing in order of preference.
        var requestedAcrValues = acrValues.Split(' ');
        foreach (var requestedAcrValue in requestedAcrValues)
        {
            if (string.IsNullOrEmpty(requestedAcrValue))
            {
                return Task.FromResult(AuthorizeRequestOidcParameterAcrValuesValidationResult.InvalidAcrValuesSyntax);
            }
        }

        return Task.FromResult(new AuthorizeRequestOidcParameterAcrValuesValidationResult(requestedAcrValues));
    }
}
