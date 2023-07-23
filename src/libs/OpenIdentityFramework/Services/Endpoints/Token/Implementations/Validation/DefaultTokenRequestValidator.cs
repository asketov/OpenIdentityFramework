using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Token.Validation;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.CommonParameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.ClientCredentials;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.RefreshToken;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation;

public class DefaultTokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    : ITokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers

{
    protected static readonly TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> UnsupportedGrantType =
        new(new ProtocolError(TokenErrors.UnsupportedGrantType, "The authorization grant type is not supported by the authorization server"));

    public DefaultTokenRequestValidator(
        ITokenRequestCommonParameterGrantTypeValidator<TRequestContext, TClient, TClientSecret> grantTypeValidator,
        ITokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> authorizationCodeValidator,
        ITokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> clientCredentialsValidator,
        ITokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> refreshTokenValidator)
    {
        ArgumentNullException.ThrowIfNull(grantTypeValidator);
        ArgumentNullException.ThrowIfNull(authorizationCodeValidator);
        ArgumentNullException.ThrowIfNull(clientCredentialsValidator);
        ArgumentNullException.ThrowIfNull(refreshTokenValidator);
        GrantTypeValidator = grantTypeValidator;
        AuthorizationCodeValidator = authorizationCodeValidator;
        ClientCredentialsValidator = clientCredentialsValidator;
        RefreshTokenValidator = refreshTokenValidator;
    }

    protected ITokenRequestCommonParameterGrantTypeValidator<TRequestContext, TClient, TClientSecret> GrantTypeValidator { get; }
    protected ITokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> AuthorizationCodeValidator { get; }
    protected ITokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ClientCredentialsValidator { get; }
    protected ITokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> RefreshTokenValidator { get; }

    public virtual async Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> ValidateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        string clientAuthenticationMethod,
        string issuer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var grantTypeValidation = await GrantTypeValidator.ValidateGrantTypeAsync(requestContext, form, client, cancellationToken);
        if (grantTypeValidation.HasError)
        {
            return new(grantTypeValidation.Error);
        }

        if (grantTypeValidation.GrantType == DefaultGrantTypes.AuthorizationCode)
        {
            var result = await AuthorizationCodeValidator.ValidateAsync(requestContext, form, client, cancellationToken);
            if (result.HasError)
            {
                return new(result.ProtocolError);
            }

            var validAuthorizationCode = new ValidAuthorizationCode<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>(
                result.ValidTokenRequest.AuthorizationCodeHandle,
                result.ValidTokenRequest.AuthorizationCode);
            var validRequest = new ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>(
                DefaultGrantTypes.AuthorizationCode,
                client,
                result.ValidTokenRequest.AllowedResources,
                result.ValidTokenRequest.ResourceOwnerProfile,
                null,
                validAuthorizationCode,
                issuer);
            return new(validRequest);
        }

        if (grantTypeValidation.GrantType == DefaultGrantTypes.ClientCredentials)
        {
            var result = await ClientCredentialsValidator.ValidateAsync(requestContext, form, client, clientAuthenticationMethod, cancellationToken);
            if (result.HasError)
            {
                return new(result.ProtocolError);
            }

            var validRequest = new ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>(
                DefaultGrantTypes.ClientCredentials,
                client,
                result.ValidTokenRequest.AllowedResources,
                null,
                null,
                null,
                issuer);
            return new(validRequest);
        }

        if (grantTypeValidation.GrantType == DefaultGrantTypes.RefreshToken)
        {
            var result = await RefreshTokenValidator.ValidateAsync(requestContext, form, client, cancellationToken);
            if (result.HasError)
            {
                return new(result.ProtocolError);
            }

            var validRefreshToken = new ValidRefreshToken<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>(
                result.ValidTokenRequest.RefreshTokenHandle,
                result.ValidTokenRequest.RefreshToken);
            var validRequest = new ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>(
                DefaultGrantTypes.RefreshToken,
                client,
                result.ValidTokenRequest.AllowedResources,
                result.ValidTokenRequest.ResourceOwnerProfile,
                validRefreshToken,
                null,
                issuer);
            return new(validRequest);
        }

        return UnsupportedGrantType;
    }
}
