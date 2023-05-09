using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.CommonParameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.CommonParameters;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.CommonParameters;

public class DefaultTokenRequestCommonParameterGrantTypeValidator<TRequestContext, TClient, TClientSecret>
    : ITokenRequestCommonParameterGrantTypeValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public virtual Task<TokenRequestCommonParameterGrantTypeValidationResult> ValidateGrantTypeAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.1
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2
        // grant_type - REQUIRED. Identifier of the grant type the client uses with the particular token request.
        // This specification defines the values "authorization_code", "refresh_token", and "client_credentials".
        if (!form.TryGetValue(TokenRequestParameters.GrantType, out var grantTypeValues) || grantTypeValues.Count == 0)
        {
            return Task.FromResult(TokenRequestCommonParameterGrantTypeValidationResult.GrantTypeIsMissing);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (grantTypeValues.Count != 1)
        {
            return Task.FromResult(TokenRequestCommonParameterGrantTypeValidationResult.MultipleGrantTypeValuesNotAllowed);
        }

        var grantType = grantTypeValues.ToString();
        if (grantType == DefaultGrantTypes.AuthorizationCode)
        {
            return Task.FromResult(TokenRequestCommonParameterGrantTypeValidationResult.AuthorizationCode);
        }

        if (grantType == DefaultGrantTypes.ClientCredentials)
        {
            return Task.FromResult(TokenRequestCommonParameterGrantTypeValidationResult.ClientCredentials);
        }

        if (grantType == DefaultGrantTypes.RefreshToken)
        {
            return Task.FromResult(TokenRequestCommonParameterGrantTypeValidationResult.RefreshToken);
        }

        return Task.FromResult(TokenRequestCommonParameterGrantTypeValidationResult.UnsupportedGrant);
    }
}
