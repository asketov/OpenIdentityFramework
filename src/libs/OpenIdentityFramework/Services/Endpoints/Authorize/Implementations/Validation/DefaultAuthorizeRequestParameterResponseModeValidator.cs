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

public class DefaultAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public virtual Task<AuthorizeRequestParameterResponseModeValidationResult> ValidateResponseModeParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        string responseType,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "response_mode" - OPTIONAL (OAuth 2.0, OpenID Connect 1.0).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.ResponseMode, out var responseModeValues) || responseModeValues.Count == 0)
        {
            return Task.FromResult(InferResponseMode(responseType));
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (responseModeValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestParameterResponseModeValidationResult.MultipleResponseModeValuesNotAllowed);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var responseMode = responseModeValues.ToString();
        if (string.IsNullOrEmpty(responseMode))
        {
            return Task.FromResult(InferResponseMode(responseType));
        }

        return Task.FromResult(ResponseModeToResult(responseMode));
    }

    protected virtual AuthorizeRequestParameterResponseModeValidationResult InferResponseMode(string responseType)
    {
        if (DefaultResponseType.ToResponseMode.TryGetValue(responseType, out var inferredResponseMode))
        {
            return ResponseModeToResult(inferredResponseMode);
        }

        return AuthorizeRequestParameterResponseModeValidationResult.UnableToInferResponseMode;
    }

    protected virtual AuthorizeRequestParameterResponseModeValidationResult ResponseModeToResult(string responseMode)
    {
        // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#rfc.section.2.1
        // https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#rfc.section.2
        if (responseMode == DefaultResponseMode.Fragment)
        {
            return AuthorizeRequestParameterResponseModeValidationResult.Fragment;
        }

        if (responseMode == DefaultResponseMode.Query)
        {
            return AuthorizeRequestParameterResponseModeValidationResult.Query;
        }

        if (responseMode == DefaultResponseMode.FormPost)
        {
            return AuthorizeRequestParameterResponseModeValidationResult.FormPost;
        }

        return AuthorizeRequestParameterResponseModeValidationResult.UnsupportedResponseMode;
    }
}
