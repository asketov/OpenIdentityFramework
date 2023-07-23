using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;

public class DefaultAuthorizeRequestParameterResponseTypeValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestParameterResponseTypeValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    public virtual Task<AuthorizeRequestParameterResponseTypeValidationResult> ValidateResponseTypeParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1 (Authorization Code)
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1 (Authorization Code)
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.1 (Hybrid Flow)
        // response_type - REQUIRED in both specs
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.ResponseType, out var responseTypeValues) || responseTypeValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestParameterResponseTypeValidationResult.ResponseTypeIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (responseTypeValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestParameterResponseTypeValidationResult.MultipleResponseTypeValuesNotAllowed);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var responseTypeString = responseTypeValues.ToString();
        if (string.IsNullOrEmpty(responseTypeString))
        {
            return Task.FromResult(AuthorizeRequestParameterResponseTypeValidationResult.ResponseTypeIsMissing);
        }

        var responseTypesArray = responseTypeString.Split(' ');
        var responseTypes = new HashSet<string>(responseTypesArray, StringComparer.Ordinal);
        if (responseTypes.Count != responseTypesArray.Length)
        {
            return Task.FromResult(AuthorizeRequestParameterResponseTypeValidationResult.UnsupportedResponseType);
        }

        var allowedGrantTypes = client.GetGrantTypes();

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // This specification defines the value "code", which must be used to signal that the client wants to use the authorization code flow.
        // Extension response types MAY contain a space-delimited (%x20) list of values, where the order of values does not matter (e.g., response type "a b" is the same as "b a").
        // The meaning of such composite response types is defined by their respective specifications.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // When using the Authorization Code Flow, this value is "code".
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.1
        // When using the Hybrid Flow, this value is "code id_token", "code token", or "code id_token token"
        // ==================================
        // OAuth 2.1 deprecates the issuance of tokens directly from the authorization endpoint. Only 'code id_token' is compatible with OAuth 2.1 and OpenID Connect 1.0
        // OpenID Connect 1.0-specific
        if (!allowedGrantTypes.Contains(DefaultGrantTypes.AuthorizationCode))
        {
            return Task.FromResult(AuthorizeRequestParameterResponseTypeValidationResult.UnsupportedResponseType);
        }

        if (parameters.IsOpenIdRequest && responseTypes.Count == DefaultResponseTypes.CodeIdToken.Count)
        {
            if (DefaultResponseTypes.CodeIdToken.SetEquals(responseTypes))
            {
                return Task.FromResult(AuthorizeRequestParameterResponseTypeValidationResult.CodeIdToken);
            }

            return Task.FromResult(AuthorizeRequestParameterResponseTypeValidationResult.UnsupportedResponseType);
        }

        // Both OAuth 2.1 and OpenID Connect 1.0
        if (DefaultResponseTypes.Code.SetEquals(responseTypes))
        {
            return Task.FromResult(AuthorizeRequestParameterResponseTypeValidationResult.Code);
        }

        return Task.FromResult(AuthorizeRequestParameterResponseTypeValidationResult.UnsupportedResponseType);
    }
}
