﻿using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Token.Validation;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.CommonParameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.ClientCredentials;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.RefreshToken;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation;

public class DefaultTokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>
    : ITokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
    where TRefreshToken : AbstractRefreshToken
{
    protected static readonly TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> UnsupportedGrantType =
        new(new ProtocolError(TokenErrors.UnsupportedGrantType, "The authorization grant type is not supported by the authorization server"));

    public DefaultTokenRequestValidator(
        ITokenRequestCommonParameterGrantTypeValidator<TRequestContext, TClient, TClientSecret> grantTypeValidator,
        ITokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> authorizationCodeValidator,
        ITokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> clientCredentialsValidator,
        ITokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> refreshTokenValidator)
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
    protected ITokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> AuthorizationCodeValidator { get; }
    protected ITokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ClientCredentialsValidator { get; }
    protected ITokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> RefreshTokenValidator { get; }

    public virtual async Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>> ValidateAsync(
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

            var validAuthorizationCode = new ValidAuthorizationCode<TAuthorizationCode>(
                result.ValidTokenRequest.AuthorizationCodeHandle,
                result.ValidTokenRequest.AuthorizationCode);
            var validRequest = new ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>(
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

            var validRequest = new ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>(
                DefaultGrantTypes.AuthorizationCode,
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

            var validRefreshToken = new ValidRefreshToken<TRefreshToken>(
                result.ValidTokenRequest.RefreshTokenHandle,
                result.ValidTokenRequest.RefreshToken);
            var validRequest = new ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>(
                DefaultGrantTypes.AuthorizationCode,
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
