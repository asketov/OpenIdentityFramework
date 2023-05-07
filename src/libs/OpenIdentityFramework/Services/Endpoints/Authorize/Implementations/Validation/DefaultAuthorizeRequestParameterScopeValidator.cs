using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;

public class DefaultAuthorizeRequestParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : IAuthorizeRequestParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultAuthorizeRequestParameterScopeValidator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IResourceValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> resourceValidator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(resourceValidator);
        FrameworkOptions = frameworkOptions;
        ResourceValidator = resourceValidator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IResourceValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ResourceValidator { get; }

    public virtual async Task<AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>> ValidateScopeParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // "scope" - OPTIONAL. The scope of the access request as described by Section 3.2.2.1.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // If the client omits the scope parameter when requesting authorization, the authorization server MUST either process the request using a pre-defined default value or fail the request indicating an invalid scope.
        // The authorization server SHOULD document its scope requirements and default value (if defined).
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // REQUIRED. OpenID Connect requests MUST contain the "openid" scope value. If the openid scope value is not present, the behavior is entirely unspecified.
        // Other scope values MAY be present. Scope values used that are not understood by an implementation SHOULD be ignored.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        string scopeParameterValue;
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.Scope, out var scopeValues)
            || scopeValues.Count == 0
            || string.IsNullOrEmpty(scopeParameterValue = scopeValues.ToString()))
        {
            if (!parameters.IsOpenIdRequest)
            {
                var defaultScopesValidation = await ResourceValidator.ValidateRequestedScopesAsync(
                    requestContext,
                    client,
                    client.GetAllowedScopes(),
                    DefaultTokenTypeFilters.AccessToken,
                    cancellationToken);
                if (defaultScopesValidation.HasError)
                {
                    if (defaultScopesValidation.Error.HasConfigurationError)
                    {
                        return AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>.Misconfigured;
                    }

                    return AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>.InvalidScope;
                }

                return new(defaultScopesValidation.Valid);
            }

            return AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>.ScopeIsMissing;
        }


        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (scopeValues.Count > 1)
        {
            return AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>.MultipleScope;
        }

        // length check
        if (scopeParameterValue.Length > FrameworkOptions.InputLengthRestrictions.Scope)
        {
            return AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>.ScopeIsTooLong;
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
                return AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>.InvalidScopeSyntax;
            }

            // length check
            if (requestedScope.Length > FrameworkOptions.InputLengthRestrictions.ScopeSingleEntry)
            {
                return AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>.ScopeIsTooLong;
            }
        }

        var tokenTypeFilter = DefaultTokenTypeFilters.AccessToken;
        if (parameters.IsOpenIdRequest)
        {
            tokenTypeFilter = DefaultTokenTypeFilters.IdTokenAccessToken;
        }

        var requestedScopesValidation = await ResourceValidator.ValidateRequestedScopesAsync(requestContext, client, requestedScopes, tokenTypeFilter, cancellationToken);
        if (requestedScopesValidation.HasError)
        {
            if (requestedScopesValidation.Error.HasConfigurationError)
            {
                return AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>.Misconfigured;
            }

            return AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>.InvalidScope;
        }

        return new(requestedScopesValidation.Valid);
    }
}
