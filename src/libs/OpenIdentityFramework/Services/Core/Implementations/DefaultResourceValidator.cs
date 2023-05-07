using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Storages.Configuration;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultResourceValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : IResourceValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultResourceValidator(IResourceStorage<TRequestContext, TScope, TResource, TResourceSecret> storage)
    {
        ArgumentNullException.ThrowIfNull(storage);
        Storage = storage;
    }

    protected IResourceStorage<TRequestContext, TScope, TResource, TResourceSecret> Storage { get; }

    public virtual async Task<ResourcesValidationResult<TScope, TResource, TResourceSecret>> ValidateRequestedScopesAsync(
        TRequestContext requestContext,
        TClient client,
        IReadOnlySet<string> requestedScopes,
        IReadOnlySet<string> tokenTypesFilter,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(requestedScopes);
        ArgumentNullException.ThrowIfNull(tokenTypesFilter);
        cancellationToken.ThrowIfCancellationRequested();

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1
        // The authorization server MAY fully or partially ignore the scope requested by the client, based on the authorization server policy or the resource owner's instructions.
        // If the issued access token scope is different from the one requested by the client, the authorization server MUST include the scope response parameter in the token response (Section 3.2.3)
        // to inform the client of the actual scope granted.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // REQUIRED. OpenID Connect requests MUST contain the "openid" scope value. If the "openid" scope value is not present, the behavior is entirely unspecified.
        // Other scope values MAY be present. Scope values used that are not understood by an implementation SHOULD be ignored.
        var clientScopes = client.GetAllowedScopes();
        var filteredScopes = clientScopes.Intersect(requestedScopes).ToHashSet(StringComparer.Ordinal);
        filteredScopes.Remove(DefaultScopes.OfflineAccess); // it depends on allowed grant type and hasn't storage-related configuration

        // errors accumulation
        var disallowedScopes = new HashSet<string>(filteredScopes.Count, StringComparer.Ordinal);
        var scopesDuplicates = new HashSet<string>();
        var resourcesDuplicates = new HashSet<string>();
        var misconfiguredScopes = new HashSet<TScope>();
        var misconfiguredResources = new HashSet<TResource>();

        // temp
        var isOpenId = filteredScopes.Contains(DefaultScopes.OpenId);
        var hasOfflineAccess = false;
        var processedScopes = new HashSet<string>();
        var idTokenScopeNames = new HashSet<string>();
        var accessTokenScopeNames = new HashSet<string>();
        var processedResourceNames = new HashSet<string>();

        // result accumulation
        var resultScopes = new HashSet<TScope>();
        var resultResources = new HashSet<TResource>();

        // process offline access
        if (requestedScopes.Contains(DefaultScopes.OfflineAccess))
        {
            if (client.GetAllowedAuthorizationFlows().Contains(DefaultAuthorizationFlows.RefreshToken))
            {
                hasOfflineAccess = true;
                processedScopes.Add(DefaultScopes.OfflineAccess);
            }
            else
            {
                disallowedScopes.Add(DefaultScopes.OfflineAccess);
            }
        }

        // get resources configuration
        var foundScopesAndRelatedResources = await Storage.FindScopesAndRelatedResourcesAsync(requestContext, filteredScopes, cancellationToken);

        // processing scopes
        foreach (var scope in foundScopesAndRelatedResources.Scopes)
        {
            var scopeName = scope.GetProtocolName();
            // we got unexpected data
            if (!filteredScopes.Contains(scopeName))
            {
                continue;
            }

            var scopeTokenType = scope.GetScopeTokenType();
            if (!tokenTypesFilter.Contains(scopeTokenType))
            {
                disallowedScopes.Add(scopeName);
            }

            if (scopeTokenType == DefaultTokenTypes.IdToken)
            {
                // need to collect "id_token" scopes for further validation (id_token scopes incompatible with OAuth 2.1)
                idTokenScopeNames.Add(scopeName);
            }
            else if (scopeTokenType == DefaultTokenTypes.AccessToken)
            {
                // need to collect "access_token" scopes for further validation (resources)
                accessTokenScopeNames.Add(scopeName);
            }
            else
            {
                // scopes are intended to use only with "id_token" and "access_token"
                misconfiguredScopes.Add(scope);
            }

            // "openid" scope MUST be an "id_token" scope
            if (scopeName == DefaultScopes.OpenId && scopeTokenType != DefaultTokenTypes.IdToken)
            {
                misconfiguredScopes.Add(scope);
            }

            // accumulate results and duplicates
            if (!processedScopes.Contains(scopeName))
            {
                processedScopes.Add(scopeName);
                resultScopes.Add(scope);
            }
            else
            {
                scopesDuplicates.Add(scopeName);
            }
        }

        // "id_token" scopes allowed only when "openid" scope provided
        if (!isOpenId && idTokenScopeNames.Count > 0)
        {
            foreach (var idTokenScopeName in idTokenScopeNames)
            {
                disallowedScopes.Add(idTokenScopeName);
            }
        }

        // requested scopes must be covered by allowed scopes
        if (!processedScopes.IsSupersetOf(requestedScopes))
        {
            foreach (var disallowedScope in requestedScopes.Except(processedScopes))
            {
                disallowedScopes.Add(disallowedScope);
            }
        }

        if (disallowedScopes.Count > 0)
        {
            return new(new ResourcesValidationError<TScope, TResource, TResourceSecret>(disallowedScopes));
        }

        // processing resources
        foreach (var resource in foundScopesAndRelatedResources.Resources)
        {
            var resourceName = resource.GetProtocolName();
            var resourceScopes = resource.GetAccessTokenScopes();
            // resource can't contain id_token scopes in allowed scopes
            if (resourceScopes.Overlaps(idTokenScopeNames))
            {
                misconfiguredResources.Add(resource);
                processedResourceNames.Add(resourceName);
                continue;
            }

            // we got unexpected data
            if (!resourceScopes.Overlaps(accessTokenScopeNames))
            {
                continue;
            }

            if (!processedResourceNames.Contains(resourceName))
            {
                processedResourceNames.Add(resourceName);
                resultResources.Add(resource);
            }
            else
            {
                resourcesDuplicates.Add(resourceName);
            }
        }

        if (scopesDuplicates.Count > 0
            || resourcesDuplicates.Count > 0
            || misconfiguredScopes.Count > 0
            || misconfiguredResources.Count > 0)
        {
            return new(new ResourcesValidationError<TScope, TResource, TResourceSecret>(new ConfigurationError<TScope, TResource, TResourceSecret>(
                scopesDuplicates,
                resourcesDuplicates,
                misconfiguredScopes,
                misconfiguredResources)));
        }

        return new(new ValidResources<TScope, TResource, TResourceSecret>(
            resultScopes,
            resultResources,
            hasOfflineAccess));
    }
}
