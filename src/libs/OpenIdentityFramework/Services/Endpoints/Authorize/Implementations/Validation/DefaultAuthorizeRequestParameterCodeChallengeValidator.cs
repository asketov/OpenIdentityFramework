using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;
using OpenIdentityFramework.Services.Static.Cryptography;
using OpenIdentityFramework.Services.Static.SyntaxValidation;
using OpenIdentityFramework.Services.Static.WebUtilities;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;

public class DefaultAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    public DefaultAuthorizeRequestParameterCodeChallengeValidator(OpenIdentityFrameworkOptions frameworkOptions)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        FrameworkOptions = frameworkOptions;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    public virtual Task<AuthorizeRequestParameterCodeChallengeValidationResult> ValidateCodeChallengeParameterAsync(
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
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.CodeChallenge, out var codeChallengeValues) || codeChallengeValues.Count == 0)
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
        if (!CodeChallengeSyntaxValidator.IsValid(codeChallenge))
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.InvalidCodeChallengeSyntax);
        }

        if (codeChallengeMethod == DefaultCodeChallengeMethod.Plain)
        {
            // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
            if (codeChallenge.Length < FrameworkOptions.InputLengthRestrictions.CodeChallengeMinLength)
            {
                return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.CodeChallengeIsTooShort);
            }

            // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
            if (codeChallenge.Length > FrameworkOptions.InputLengthRestrictions.CodeChallengeMaxLength)
            {
                return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.CodeChallengeIsTooLong);
            }
        }

        if (codeChallengeMethod == DefaultCodeChallengeMethod.S256 && !IsValidBase64Sha256Value(codeChallenge))
        {
            return Task.FromResult(AuthorizeRequestParameterCodeChallengeValidationResult.InvalidCodeChallengeSyntax);
        }

        return Task.FromResult(new AuthorizeRequestParameterCodeChallengeValidationResult(codeChallenge));
    }

    protected virtual bool IsValidBase64Sha256Value(string base64EncodedCodeChallenge)
    {
        const int maxStackallocBytesCount = 1024;
        if (string.IsNullOrEmpty(base64EncodedCodeChallenge))
        {
            return false;
        }

        var base64DecodedCodeChallengeBufferSize = Base64UrlDecoder.ComputeRequiredBufferSize(base64EncodedCodeChallenge.Length);
        byte[]? base64DecodedCodeChallengeBufferFromPool = null;
        var base64DecodedCodeChallengeBuffer = base64DecodedCodeChallengeBufferSize <= maxStackallocBytesCount
            ? stackalloc byte[maxStackallocBytesCount]
            : base64DecodedCodeChallengeBufferFromPool = ArrayPool<byte>.Shared.Rent(base64DecodedCodeChallengeBufferSize);
        try
        {
            return Base64UrlDecoder.TryDecode(base64EncodedCodeChallenge, base64DecodedCodeChallengeBuffer, out var base64BytesCount)
                   && base64BytesCount == Sha256Hasher.Sha256BytesCount;
        }
        finally
        {
            if (base64DecodedCodeChallengeBufferFromPool is not null)
            {
                ArrayPool<byte>.Shared.Return(base64DecodedCodeChallengeBufferFromPool, true);
            }
            else
            {
                base64DecodedCodeChallengeBuffer.Clear();
            }
        }
    }
}
