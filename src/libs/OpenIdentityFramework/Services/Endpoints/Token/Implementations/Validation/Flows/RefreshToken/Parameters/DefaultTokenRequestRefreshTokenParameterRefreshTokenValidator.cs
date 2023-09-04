using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.RefreshToken.Parameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.RefreshToken.Parameters;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.RefreshToken.Parameters;

public class DefaultTokenRequestRefreshTokenParameterRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    : ITokenRequestRefreshTokenParameterRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultTokenRequestRefreshTokenParameterRefreshTokenValidator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> refreshTokens)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(refreshTokens);
        FrameworkOptions = frameworkOptions;
        RefreshTokens = refreshTokens;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> RefreshTokens { get; }


    public virtual async Task<TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> ValidateRefreshTokenAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-4.3.1
        // "refresh_token" - REQUIRED. The refresh token issued to the client.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.12
        // A request to the Token Endpoint can also use a Refresh Token by using the grant_type value refresh_token, as described in Section 6 of OAuth 2.0 [RFC6749].
        // This section defines the behaviors for OpenID Connect Authorization Servers when Refresh Tokens are used.
        if (!form.TryGetValue(TokenRequestParameters.RefreshToken, out var refreshTokenValues))
        {
            return TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.RefreshTokenIsMissing;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-3.2
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (refreshTokenValues.Count != 1)
        {
            return TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.MultipleRefreshTokenValuesNotAllowed;
        }

        var refreshTokenHandle = refreshTokenValues.ToString();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-09.html#section-3.2
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (string.IsNullOrEmpty(refreshTokenHandle))
        {
            return TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.RefreshTokenIsMissing;
        }

        if (refreshTokenHandle.Length > FrameworkOptions.InputLengthRestrictions.RefreshToken)
        {
            return TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.RefreshTokenIsTooLong;
        }

        var refreshToken = await RefreshTokens.FindAsync(requestContext, client, refreshTokenHandle, cancellationToken);
        if (refreshToken is not null)
        {
            return new(refreshTokenHandle, refreshToken);
        }

        return TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.UnknownRefreshToken;
    }
}
