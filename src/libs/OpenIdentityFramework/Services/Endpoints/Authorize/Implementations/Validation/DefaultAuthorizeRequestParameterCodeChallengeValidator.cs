using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants.Request.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;

public class DefaultAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public Task<AuthorizeRequestParameterCodeChallengeValidationResult> ValidateCodeChallengeParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        string codeChallengeMethod,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-7.6.1
        // To prevent injection of authorization codes into the client, using code_challenge and code_verifier is REQUIRED for clients,
        // and authorization servers MUST enforce their use, unless both of the following criteria are met:
        // * The client is a confidential client.
        // * In the specific deployment and the specific request, there is reasonable assurance by the authorization server that the client implements the OpenID Connect "nonce" mechanism properly.
        // In this case, using and enforcing code_challenge and code_verifier is still RECOMMENDED.
        // ------
        // In current implementation "code_challenge" is required.
        if (!parameters.Raw.TryGetValue(RequestParameters.CodeChallenge, out var codeChallengeValues) || codeChallengeValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.CodeChallengeIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeChallengeValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.MultipleCodeChallenge);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var codeChallenge = codeChallengeValues.ToString();
        if (string.IsNullOrEmpty(codeChallenge))
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.CodeChallengeIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
        if (codeChallenge.Length < 43)
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.CodeChallengeIsTooShort);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
        if (codeChallenge.Length > 128)
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.CodeChallengeIsTooLong);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
        if (!CodeChallengeSyntaxValidator.IsValid(codeChallenge))
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.InvalidCodeChallengeSyntax);
        }

        if (codeChallengeMethod == CodeChallengeMethod.S256 && !HexValidator.IsValid(codeChallenge))
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.InvalidCodeChallengeSyntax);
        }

        return Task.FromResult(new AuthorizeRequestParameterCodeChallengeValidationResult(codeChallenge));
    }
}
