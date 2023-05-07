using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.ClientCredentials;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.CommonParameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.ClientCredentials;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.ClientCredentials;

public class DefaultTokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : ITokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    protected static readonly TokenRequestClientCredentialsValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> UnauthorizedClient =
        new(new ProtocolError(TokenErrors.UnauthorizedClient, "The authenticated client is not authorized to use this authorization grant type"));

    public DefaultTokenRequestClientCredentialsValidator(
        ITokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> scopeValidator)
    {
        ArgumentNullException.ThrowIfNull(scopeValidator);
        ScopeValidator = scopeValidator;
    }

    protected ITokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ScopeValidator { get; }

    public virtual async Task<TokenRequestClientCredentialsValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> ValidateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        string clientAuthenticationMethod,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        if (!client.GetAllowedAuthorizationFlows().Contains(DefaultAuthorizationFlows.ClientCredentials))
        {
            return UnauthorizedClient;
        }

        if (client.GetClientType() != DefaultClientTypes.Confidential)
        {
            return UnauthorizedClient;
        }

        if (clientAuthenticationMethod == DefaultClientAuthenticationMethods.None)
        {
            return UnauthorizedClient;
        }

        var scopeValidation = await ScopeValidator.ValidateScopeAsync(requestContext, form, client, client.GetAllowedScopes(), cancellationToken);
        if (scopeValidation.HasError)
        {
            return new(scopeValidation.Error);
        }

        return new(new ValidClientCredentialsTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            client,
            scopeValidation.AllowedResources));
    }
}
