using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode.Parameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode.Parameters;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.AuthorizationCode.Parameters;

public class DefaultTokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode>
    : ITokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public DefaultTokenRequestAuthorizationCodeParameterRedirectUriValidator(OpenIdentityFrameworkOptions frameworkOptions)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        FrameworkOptions = frameworkOptions;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    public Task<TokenRequestAuthorizationCodeParameterRedirectUriValidationResult> ValidateRedirectUriAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        TAuthorizationCode authorizationCode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(authorizationCode);
        cancellationToken.ThrowIfCancellationRequested();
        var originalRedirectUri = authorizationCode.GetAuthorizeRequestRedirectUri();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.3
        // "redirect_uri" - REQUIRED, if the redirect_uri parameter was included in the authorization request as described in Section 4.1.1,
        // in which case their values MUST be identical. If no redirect_uri was included in the authorization request, this parameter is OPTIONAL.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.2
        // If the redirect_uri parameter value is not present when there is only one registered redirect_uri value,
        // the Authorization Server MAY return an error (since the Client should have included the parameter)
        // or MAY proceed without an error (since OAuth 2.0 permits the parameter to be omitted in this case).
        if (!form.TryGetValue(TokenRequestParameters.RedirectUri, out var redirectUriValues) || redirectUriValues.Count == 0)
        {
            return Task.FromResult(HandleEmptyTokenRequestParameter(originalRedirectUri));
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (redirectUriValues.Count != 1)
        {
            return Task.FromResult(TokenRequestAuthorizationCodeParameterRedirectUriValidationResult.MultipleRedirectUriValuesNotAllowed);
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
            return Task.FromResult(TokenRequestAuthorizationCodeParameterRedirectUriValidationResult.RedirectUriIsTooLong);
        }

        if (string.Equals(redirectUriString, originalRedirectUri, StringComparison.Ordinal))
        {
            return Task.FromResult(new TokenRequestAuthorizationCodeParameterRedirectUriValidationResult(redirectUriString));
        }

        return Task.FromResult(TokenRequestAuthorizationCodeParameterRedirectUriValidationResult.InvalidRedirectUri);
    }

    private static TokenRequestAuthorizationCodeParameterRedirectUriValidationResult HandleEmptyTokenRequestParameter(string? originalRedirectUri)
    {
        if (originalRedirectUri is null)
        {
            return TokenRequestAuthorizationCodeParameterRedirectUriValidationResult.Null;
        }

        return TokenRequestAuthorizationCodeParameterRedirectUriValidationResult.RedirectUriIsMissing;
    }
}
