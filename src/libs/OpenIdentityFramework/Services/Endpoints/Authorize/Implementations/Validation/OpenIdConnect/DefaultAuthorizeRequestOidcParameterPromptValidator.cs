using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation.OpenIdConnect;

public class DefaultAuthorizeRequestOidcParameterPromptValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestOidcParameterPromptValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public virtual Task<AuthorizeRequestOidcParameterPromptValidationResult> ValidatePromptOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "prompt" - OPTIONAL. Space delimited, case sensitive list of ASCII string values
        // that specifies whether the Authorization Server prompts the End-User for re-authentication and consent.
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.Prompt, out var promptValues) || promptValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterPromptValidationResult.Null);
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (promptValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterPromptValidationResult.MultiplePrompt);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var prompt = promptValues.ToString();
        if (string.IsNullOrEmpty(prompt))
        {
            // if prompt provided - it must contain valid value, otherwise it shouldn't be included in request
            return Task.FromResult(AuthorizeRequestOidcParameterPromptValidationResult.Null);
        }

        // Space delimited, case sensitive list of ASCII string values
        var requestedPrompts = prompt
            .Split(' ')
            .ToHashSet(StringComparer.Ordinal);
        // syntax validation
        foreach (var requestedPrompt in requestedPrompts)
        {
            if (string.IsNullOrWhiteSpace(requestedPrompt) || (prompt != DefaultPrompt.None && prompt != DefaultPrompt.Login && prompt != DefaultPrompt.Consent && prompt != DefaultPrompt.SelectAccount))
            {
                return Task.FromResult(AuthorizeRequestOidcParameterPromptValidationResult.UnsupportedPrompt);
            }
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // If this parameter contains "none" with any other value, an error is returned.
        if (requestedPrompts.Contains(DefaultPrompt.None) && requestedPrompts.Count > 1)
        {
            return Task.FromResult(AuthorizeRequestOidcParameterPromptValidationResult.UnsupportedPrompt);
        }

        return Task.FromResult(new AuthorizeRequestOidcParameterPromptValidationResult(requestedPrompts));
    }
}
