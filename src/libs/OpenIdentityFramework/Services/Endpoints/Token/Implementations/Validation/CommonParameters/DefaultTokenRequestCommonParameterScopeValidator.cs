using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.CommonParameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.CommonParameters;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.CommonParameters;

public class DefaultTokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : ITokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
{
    public DefaultTokenRequestCommonParameterScopeValidator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IResourceService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> resourceService)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(resourceService);
        FrameworkOptions = frameworkOptions;
        ResourceService = resourceService;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IResourceService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ResourceService { get; }

    public virtual async Task<TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>> ValidateScopeAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        IReadOnlySet<string> grantedScopes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(grantedScopes);
        cancellationToken.ThrowIfCancellationRequested();
        string scopeParameterValue;
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // The authorization and token endpoints allow the client to specify the scope of the access request using the scope request parameter.
        // In turn, the authorization server uses the scope response parameter to inform the client of the scope of the access token issued.
        if (!form.TryGetValue(TokenRequestParameters.Scope, out var scopeValues)
            || scopeValues.Count == 0
            || string.IsNullOrEmpty(scopeParameterValue = scopeValues.ToString()))
        {
            scopeParameterValue = string.Join(' ', grantedScopes);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (scopeValues.Count > 1)
        {
            return TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>.MultipleScope;
        }

        // length check
        if (scopeParameterValue.Length > FrameworkOptions.InputLengthRestrictions.Scope)
        {
            return TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>.ScopeIsTooLong;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings. The strings are defined by the authorization server.
        // If the value contains multiple space-delimited strings, their order does not matter, and each string adds an additional access range to the requested scope.
        var requestedScopes = scopeParameterValue
            .Split(' ')
            .ToHashSet(StringComparer.Ordinal);

        foreach (var requestedScope in requestedScopes)
        {
            // syntax validation
            if (string.IsNullOrEmpty(requestedScope) && !ScopeSyntaxValidator.IsValid(requestedScope))
            {
                return TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>.InvalidScopeSyntax;
            }

            // length check
            if (requestedScope.Length > FrameworkOptions.InputLengthRestrictions.ScopeSingleEntry)
            {
                return TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>.ScopeIsTooLong;
            }
        }

        if (!grantedScopes.IsSupersetOf(requestedScopes))
        {
            return TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>.InvalidScope;
        }

        var allowedTokenTypes = DefaultTokenTypeFilters.AccessToken;
        if (requestedScopes.Contains(DefaultScopes.OpenId))
        {
            allowedTokenTypes = DefaultTokenTypeFilters.IdTokenAccessToken;
        }

        var requestedScopesValidation = await ResourceService.ValidateRequestedScopesAsync(requestContext, client, requestedScopes, allowedTokenTypes, cancellationToken);
        if (requestedScopesValidation.HasError)
        {
            if (requestedScopesValidation.Error.HasConfigurationError)
            {
                return TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>.Misconfigured;
            }

            return TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>.InvalidScope;
        }

        return new(requestedScopesValidation.Valid);
    }
}
