using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.ResourceService;
using OpenIdentityFramework.Services.Endpoints.Discovery.Models.DiscoveryResponseGenerator;

namespace OpenIdentityFramework.Services.Endpoints.Discovery.Implementations;

[SuppressMessage("ReSharper", "IdentifierTypo")]
public class DefaultDiscoveryResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : IDiscoveryResponseGenerator<TRequestContext>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultDiscoveryResponseGenerator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IMemoryCache cache,
        IResourceService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> resources,
        IKeyMaterialService<TRequestContext> keyMaterialService,
        IClientAuthenticationService<TRequestContext, TClient, TClientSecret> clientAuthentication)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(keyMaterialService);
        ArgumentNullException.ThrowIfNull(clientAuthentication);
        FrameworkOptions = frameworkOptions;
        Cache = cache;
        Resources = resources;
        KeyMaterialService = keyMaterialService;
        ClientAuthentication = clientAuthentication;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IMemoryCache Cache { get; }
    protected IResourceService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> Resources { get; }
    protected IKeyMaterialService<TRequestContext> KeyMaterialService { get; }
    protected IClientAuthenticationService<TRequestContext, TClient, TClientSecret> ClientAuthentication { get; }

    public virtual async Task<DiscoveryDocument> CreateDiscoveryDocumentAsync(TRequestContext requestContext, string issuer, CancellationToken cancellationToken)
    {
        const string cacheKey = "OpenIdentityFramework_Oidc_DiscoveryDocument";
        if (FrameworkOptions.Endpoints.Discovery.DiscoveryDocumentInMemoryCacheInterval.HasValue
            && FrameworkOptions.Endpoints.Discovery.DiscoveryDocumentInMemoryCacheInterval.Value > TimeSpan.Zero)
        {
            if (Cache.TryGetValue<DiscoveryDocument>(cacheKey, out var cachedDocument) && cachedDocument is not null)
            {
                return cachedDocument;
            }

            var discoveryDoc = await BuildDiscoveryDocumentAsync(requestContext, issuer, cancellationToken);
            Cache.Set(cacheKey, discoveryDoc, FrameworkOptions.Endpoints.Discovery.DiscoveryDocumentInMemoryCacheInterval.Value);
            return discoveryDoc;
        }
        else
        {
            var discoveryDoc = await BuildDiscoveryDocumentAsync(requestContext, issuer, cancellationToken);
            return discoveryDoc;
        }
    }

    protected virtual async Task<DiscoveryDocument> BuildDiscoveryDocumentAsync(TRequestContext requestContext, string issuer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var baseUri = new Uri(issuer, UriKind.Absolute);
        var authorizationEndpoint = GetAuthorizationEndpoint(baseUri);
        var tokenEndpoint = GetTokenEndpoint(baseUri);
        var userinfoEndpoint = GetUserinfoEndpoint(baseUri);
        var jwksUri = GetJwksUri(baseUri);
        IReadOnlyCollection<string>? scopesSupported = null;
        IReadOnlyCollection<string>? claimsSupported = null!;
        if (FrameworkOptions.Endpoints.Discovery.ShowScopesSupported || FrameworkOptions.Endpoints.Discovery.ShowClaimsSupported)
        {
            var scopesAndClaims = await Resources.FindDiscoveryEndpointResourcesAsync(
                requestContext,
                DefaultTokenTypeFilters.IdTokenAccessToken,
                cancellationToken);
            scopesSupported = GetScopesSupported(scopesAndClaims);
            claimsSupported = GetClaimsSupported(scopesAndClaims);
        }

        var responseTypesSupported = GetResponseTypesSupported();
        var responseModesSupported = GetResponseModesSupported();
        var grantTypesSupported = GetGrantTypesSupported();
        var subjectTypesSupported = GetSubjectTypesSupported();
        var idTokenSigningAlgValuesSupported = await GetIdTokenSigningAlgValuesSupportedAsync(requestContext, cancellationToken);
        var tokenEndpointAuthMethodsSupported = await GetTokenEndpointAuthMethodsSupportedAsync(requestContext, cancellationToken);
        var displayValuesSupported = GetDisplayValuesSupported();
        var result = new DiscoveryDocument(
            issuer,
            authorizationEndpoint,
            tokenEndpoint,
            userinfoEndpoint,
            jwksUri,
            null,
            scopesSupported,
            responseTypesSupported,
            responseModesSupported,
            grantTypesSupported,
            null,
            subjectTypesSupported,
            idTokenSigningAlgValuesSupported,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            tokenEndpointAuthMethodsSupported,
            null,
            displayValuesSupported,
            null,
            claimsSupported,
            null,
            null,
            null,
            false,
            false,
            false,
            null,
            null,
            null,
            null);
        return result;
    }

    protected virtual string BuildAbsoluteUri(Uri baseUri, string relative)
    {
        var relativeUri = new Uri(relative, UriKind.Relative);
        var absolute = new Uri(baseUri, relativeUri);
        return absolute.ToString();
    }

    protected virtual string GetAuthorizationEndpoint(Uri baseUri)
    {
        return BuildAbsoluteUri(baseUri, FrameworkOptions.Endpoints.Authorize.Path);
    }

    protected virtual string GetTokenEndpoint(Uri baseUri)
    {
        return BuildAbsoluteUri(baseUri, FrameworkOptions.Endpoints.Token.Path);
    }

    protected virtual string? GetUserinfoEndpoint(Uri baseUri)
    {
        if (FrameworkOptions.Endpoints.UserInfo.Enable)
        {
            return BuildAbsoluteUri(baseUri, FrameworkOptions.Endpoints.UserInfo.Path);
        }

        return null;
    }

    protected virtual string GetJwksUri(Uri baseUri)
    {
        return BuildAbsoluteUri(baseUri, FrameworkOptions.Endpoints.Jwks.Path);
    }

    protected virtual IReadOnlyCollection<string>? GetScopesSupported(DiscoveryEndpointResourcesSearchResult resourcesAndClaimsResult)
    {
        ArgumentNullException.ThrowIfNull(resourcesAndClaimsResult);
        if (!FrameworkOptions.Endpoints.Discovery.ShowScopesSupported)
        {
            return null;
        }

        var result = new HashSet<string>(resourcesAndClaimsResult.Scopes.Count + 2, StringComparer.Ordinal)
        {
            DefaultScopes.OpenId,
            DefaultScopes.OfflineAccess
        };
        foreach (var scope in resourcesAndClaimsResult.Scopes)
        {
            result.Add(scope);
        }

        return result;
    }

    protected virtual IReadOnlyCollection<string> GetResponseTypesSupported()
    {
        return DefaultResponseType.Supported;
    }

    protected virtual IReadOnlyCollection<string>? GetResponseModesSupported()
    {
        if (!FrameworkOptions.Endpoints.Discovery.ShowResponseModesSupported)
        {
            return null;
        }

        return DefaultResponseMode.Supported;
    }

    protected virtual IReadOnlyCollection<string>? GetGrantTypesSupported()
    {
        if (!FrameworkOptions.Endpoints.Discovery.ShowGrantTypesSupported)
        {
            return null;
        }

        return DefaultGrantTypes.Supported;
    }

    protected virtual IReadOnlyCollection<string> GetSubjectTypesSupported()
    {
        return DefaultSubjectTypes.Supported;
    }

    protected virtual async Task<IReadOnlyCollection<string>> GetIdTokenSigningAlgValuesSupportedAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await KeyMaterialService.GetAllSigningCredentialsAlgorithmsAsync(requestContext, cancellationToken);
    }


    protected virtual async Task<IReadOnlyCollection<string>?> GetTokenEndpointAuthMethodsSupportedAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!FrameworkOptions.Endpoints.Discovery.ShowTokenEndpointAuthMethodsSupported)
        {
            return null;
        }

        return await ClientAuthentication.GetSupportedAuthenticationMethodsAsync(requestContext, cancellationToken);
    }

    protected virtual IReadOnlyCollection<string>? GetDisplayValuesSupported()
    {
        if (!FrameworkOptions.Endpoints.Discovery.ShowDisplayValuesSupported)
        {
            return null;
        }

        return DefaultDisplay.Supported;
    }

    protected virtual IReadOnlyCollection<string>? GetClaimsSupported(DiscoveryEndpointResourcesSearchResult resourcesAndClaimsResult)
    {
        ArgumentNullException.ThrowIfNull(resourcesAndClaimsResult);
        if (!FrameworkOptions.Endpoints.Discovery.ShowClaimsSupported)
        {
            return null;
        }

        var result = new HashSet<string>(resourcesAndClaimsResult.UserClaimTypes, StringComparer.Ordinal);
        foreach (var claimType in resourcesAndClaimsResult.UserClaimTypes)
        {
            result.Add(claimType);
        }

        return result;
    }
}
