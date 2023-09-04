using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;

public class DefaultAuthorizeRequestParameterCodeChallengeMethodValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestParameterCodeChallengeMethodValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    public virtual Task<AuthorizeRequestParameterCodeChallengeMethodValidationResult> ValidateCodeChallengeMethodParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-4.1.1
        // "code_challenge_method" - OPTIONAL, defaults to "plain" if not present in the request. Code verifier transformation method is "S256" or "plain".
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var allowedCodeChallengeMethods = client.GetAllowedCodeChallengeMethods();
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.CodeChallengeMethod, out var codeChallengeMethodValues) || codeChallengeMethodValues.Count == 0)
        {
            if (allowedCodeChallengeMethods.Contains(DefaultCodeChallengeMethod.Plain))
            {
                return Task.FromResult(AuthorizeRequestParameterCodeChallengeMethodValidationResult.Plain);
            }

            return Task.FromResult(AuthorizeRequestParameterCodeChallengeMethodValidationResult.CodeChallengeMethodIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeChallengeMethodValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeMethodValidationResult.MultipleCodeChallengeMethod);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var codeChallengeMethod = codeChallengeMethodValues.ToString();
        if (string.IsNullOrEmpty(codeChallengeMethod))
        {
            if (allowedCodeChallengeMethods.Contains(DefaultCodeChallengeMethod.Plain))
            {
                return Task.FromResult(AuthorizeRequestParameterCodeChallengeMethodValidationResult.Plain);
            }

            return Task.FromResult(AuthorizeRequestParameterCodeChallengeMethodValidationResult.CodeChallengeMethodIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-4.1.1
        // Code verifier transformation method is "S256" or "plain".
        if (codeChallengeMethod == DefaultCodeChallengeMethod.Plain && allowedCodeChallengeMethods.Contains(DefaultCodeChallengeMethod.Plain))
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeMethodValidationResult.Plain);
        }

        if (codeChallengeMethod == DefaultCodeChallengeMethod.S256 && allowedCodeChallengeMethods.Contains(DefaultCodeChallengeMethod.S256))
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeMethodValidationResult.S256);
        }

        return Task.FromResult(AuthorizeRequestParameterCodeChallengeMethodValidationResult.UnknownCodeChallengeMethod);
    }
}
