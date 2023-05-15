using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Configuration.Builder;
using OpenIdentityFramework.Configuration.DependencyInjection.Extensions;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.InMemory.Models.Configuration;
using OpenIdentityFramework.InMemory.Models.Operation;
using OpenIdentityFramework.InMemory.Services.Operation.RequestContextFactory;
using OpenIdentityFramework.InMemory.Services.Operation.ResourceOwnerEssentialClaimsFactory;
using OpenIdentityFramework.InMemory.Storages.Configuration;
using OpenIdentityFramework.InMemory.Storages.Operation;
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Storages.Configuration;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.InMemory.Configuration.DependencyInjection.Extensions;

public static class ServiceCollectionExtensions
{
    public static IOpenIdentityFrameworkBuilder<
            InMemoryRequestContext,
            InMemoryClient,
            InMemoryClientSecret,
            InMemoryScope,
            InMemoryResource,
            InMemoryResourceSecret,
            InMemoryAuthorizeRequestError,
            InMemoryResourceOwnerEssentialClaims,
            InMemoryResourceOwnerIdentifiers,
            InMemoryAuthorizeRequest,
            InMemoryAuthorizeRequestConsent,
            InMemoryGrantedConsent,
            InMemoryAuthorizationCode,
            InMemoryAccessToken,
            InMemoryRefreshToken>
        AddInMemoryOpenIdentityFrameworkBuilder(
            this IServiceCollection services,
            Action<OpenIdentityFrameworkOptions>? configure = null)
    {
        return services.AddOpenIdentityFrameworkBuilder<
            InMemoryRequestContext,
            InMemoryClient,
            InMemoryClientSecret,
            InMemoryScope,
            InMemoryResource,
            InMemoryResourceSecret,
            InMemoryAuthorizeRequestError,
            InMemoryResourceOwnerEssentialClaims,
            InMemoryResourceOwnerIdentifiers,
            InMemoryAuthorizeRequest,
            InMemoryAuthorizeRequestConsent,
            InMemoryGrantedConsent,
            InMemoryAuthorizationCode,
            InMemoryAccessToken,
            InMemoryRefreshToken>(configure);
    }

    public static IOpenIdentityFrameworkBuilder<
            InMemoryRequestContext,
            InMemoryClient,
            InMemoryClientSecret,
            InMemoryScope,
            InMemoryResource,
            InMemoryResourceSecret,
            InMemoryAuthorizeRequestError,
            InMemoryResourceOwnerEssentialClaims,
            InMemoryResourceOwnerIdentifiers,
            InMemoryAuthorizeRequest,
            InMemoryAuthorizeRequestConsent,
            InMemoryGrantedConsent,
            InMemoryAuthorizationCode,
            InMemoryAccessToken,
            InMemoryRefreshToken>
        AddInMemoryServices(
            this IOpenIdentityFrameworkBuilder<
                InMemoryRequestContext,
                InMemoryClient,
                InMemoryClientSecret,
                InMemoryScope,
                InMemoryResource,
                InMemoryResourceSecret,
                InMemoryAuthorizeRequestError,
                InMemoryResourceOwnerEssentialClaims,
                InMemoryResourceOwnerIdentifiers,
                InMemoryAuthorizeRequest,
                InMemoryAuthorizeRequestConsent,
                InMemoryGrantedConsent,
                InMemoryAuthorizationCode,
                InMemoryAccessToken,
                InMemoryRefreshToken> builder,
            Action<InMemoryResourceOwnerEssentialClaimsFactoryOptions>? configureClaimsFactory = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<
            IEqualityComparer<InMemoryResourceOwnerIdentifiers>,
            InMemoryResourceOwnerIdentifiersEqualityComparer>();
        builder.Services.TryAddSingleton<
            IRequestContextFactory<InMemoryRequestContext>,
            InMemoryRequestContextFactory>();
        builder.Services.TryAddSingleton<
            IResourceOwnerEssentialClaimsFactory<InMemoryRequestContext, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>,
            InMemoryResourceOwnerEssentialClaimsFactory>();
        builder.Services.Configure<InMemoryResourceOwnerEssentialClaimsFactoryOptions>(claimsFactoryOptions => configureClaimsFactory?.Invoke(claimsFactoryOptions));
        return builder;
    }

    public static IOpenIdentityFrameworkBuilder<
            InMemoryRequestContext,
            InMemoryClient,
            InMemoryClientSecret,
            InMemoryScope,
            InMemoryResource,
            InMemoryResourceSecret,
            InMemoryAuthorizeRequestError,
            InMemoryResourceOwnerEssentialClaims,
            InMemoryResourceOwnerIdentifiers,
            InMemoryAuthorizeRequest,
            InMemoryAuthorizeRequestConsent,
            InMemoryGrantedConsent,
            InMemoryAuthorizationCode,
            InMemoryAccessToken,
            InMemoryRefreshToken>
        AddInMemoryStorages(
            this IOpenIdentityFrameworkBuilder<
                InMemoryRequestContext,
                InMemoryClient,
                InMemoryClientSecret,
                InMemoryScope,
                InMemoryResource,
                InMemoryResourceSecret,
                InMemoryAuthorizeRequestError,
                InMemoryResourceOwnerEssentialClaims,
                InMemoryResourceOwnerIdentifiers,
                InMemoryAuthorizeRequest,
                InMemoryAuthorizeRequestConsent,
                InMemoryGrantedConsent,
                InMemoryAuthorizationCode,
                InMemoryAccessToken,
                InMemoryRefreshToken> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        // Operation
        builder.Services.TryAddSingleton<
            IAccessTokenStorage<InMemoryRequestContext, InMemoryAccessToken, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>,
            InMemoryAccessTokenStorage>();
        builder.Services.TryAddSingleton<
            IAuthorizationCodeStorage<InMemoryRequestContext, InMemoryAuthorizationCode, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>,
            InMemoryAuthorizationCodeStorage>();
        builder.Services.TryAddSingleton<
            IAuthorizeRequestConsentStorage<InMemoryRequestContext, InMemoryAuthorizeRequestConsent, InMemoryResourceOwnerIdentifiers>,
            InMemoryAuthorizeRequestConsentStorage>();
        builder.Services.TryAddSingleton<
            IAuthorizeRequestErrorStorage<InMemoryRequestContext, InMemoryAuthorizeRequestError>,
            InMemoryAuthorizeRequestErrorStorage>();
        builder.Services.TryAddSingleton<
            IAuthorizeRequestStorage<InMemoryRequestContext, InMemoryAuthorizeRequest>,
            InMemoryAuthorizeRequestStorage>();
        builder.Services.TryAddSingleton<
            IGrantedConsentStorage<InMemoryRequestContext, InMemoryGrantedConsent>,
            InMemoryGrantedConsentStorage>();
        builder.Services.TryAddSingleton<
            IRefreshTokenStorage<InMemoryRequestContext, InMemoryRefreshToken, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>,
            InMemoryRefreshTokenStorage>();

        // Configuration
        builder.Services.TryAddSingleton<
            IClientStorage<InMemoryRequestContext, InMemoryClient, InMemoryClientSecret>,
            InMemoryClientStorage>();
        builder.Services.TryAddSingleton<
            IKeyMaterialStorage<InMemoryRequestContext>,
            InMemoryKeyMaterialStorage>();
        builder.Services.TryAddSingleton<
            IResourceStorage<InMemoryRequestContext, InMemoryScope, InMemoryResource, InMemoryResourceSecret>,
            InMemoryResourceStorage>();
        return builder;
    }

    public static IOpenIdentityFrameworkBuilder<
            InMemoryRequestContext,
            InMemoryClient,
            InMemoryClientSecret,
            InMemoryScope,
            InMemoryResource,
            InMemoryResourceSecret,
            InMemoryAuthorizeRequestError,
            InMemoryResourceOwnerEssentialClaims,
            InMemoryResourceOwnerIdentifiers,
            InMemoryAuthorizeRequest,
            InMemoryAuthorizeRequestConsent,
            InMemoryGrantedConsent,
            InMemoryAuthorizationCode,
            InMemoryAccessToken,
            InMemoryRefreshToken>
        AddInMemoryClients(
            this IOpenIdentityFrameworkBuilder<
                InMemoryRequestContext,
                InMemoryClient,
                InMemoryClientSecret,
                InMemoryScope,
                InMemoryResource,
                InMemoryResourceSecret,
                InMemoryAuthorizeRequestError,
                InMemoryResourceOwnerEssentialClaims,
                InMemoryResourceOwnerIdentifiers,
                InMemoryAuthorizeRequest,
                InMemoryAuthorizeRequestConsent,
                InMemoryGrantedConsent,
                InMemoryAuthorizationCode,
                InMemoryAccessToken,
                InMemoryRefreshToken> builder,
            IEnumerable<InMemoryClient>? clients)
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (clients is not null)
        {
            foreach (var client in clients)
            {
                builder.Services.AddSingleton(client);
            }
        }

        return builder;
    }

    public static IOpenIdentityFrameworkBuilder<
            InMemoryRequestContext,
            InMemoryClient,
            InMemoryClientSecret,
            InMemoryScope,
            InMemoryResource,
            InMemoryResourceSecret,
            InMemoryAuthorizeRequestError,
            InMemoryResourceOwnerEssentialClaims,
            InMemoryResourceOwnerIdentifiers,
            InMemoryAuthorizeRequest,
            InMemoryAuthorizeRequestConsent,
            InMemoryGrantedConsent,
            InMemoryAuthorizationCode,
            InMemoryAccessToken,
            InMemoryRefreshToken>
        AddInMemoryResources(
            this IOpenIdentityFrameworkBuilder<
                InMemoryRequestContext,
                InMemoryClient,
                InMemoryClientSecret,
                InMemoryScope,
                InMemoryResource,
                InMemoryResourceSecret,
                InMemoryAuthorizeRequestError,
                InMemoryResourceOwnerEssentialClaims,
                InMemoryResourceOwnerIdentifiers,
                InMemoryAuthorizeRequest,
                InMemoryAuthorizeRequestConsent,
                InMemoryGrantedConsent,
                InMemoryAuthorizationCode,
                InMemoryAccessToken,
                InMemoryRefreshToken> builder,
            IEnumerable<InMemoryResource>? resources)
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (resources is not null)
        {
            foreach (var resource in resources)
            {
                builder.Services.AddSingleton(resource);
            }
        }

        return builder;
    }

    public static IOpenIdentityFrameworkBuilder<
            InMemoryRequestContext,
            InMemoryClient,
            InMemoryClientSecret,
            InMemoryScope,
            InMemoryResource,
            InMemoryResourceSecret,
            InMemoryAuthorizeRequestError,
            InMemoryResourceOwnerEssentialClaims,
            InMemoryResourceOwnerIdentifiers,
            InMemoryAuthorizeRequest,
            InMemoryAuthorizeRequestConsent,
            InMemoryGrantedConsent,
            InMemoryAuthorizationCode,
            InMemoryAccessToken,
            InMemoryRefreshToken>
        AddInMemoryScopes(
            this IOpenIdentityFrameworkBuilder<
                InMemoryRequestContext,
                InMemoryClient,
                InMemoryClientSecret,
                InMemoryScope,
                InMemoryResource,
                InMemoryResourceSecret,
                InMemoryAuthorizeRequestError,
                InMemoryResourceOwnerEssentialClaims,
                InMemoryResourceOwnerIdentifiers,
                InMemoryAuthorizeRequest,
                InMemoryAuthorizeRequestConsent,
                InMemoryGrantedConsent,
                InMemoryAuthorizationCode,
                InMemoryAccessToken,
                InMemoryRefreshToken> builder,
            IEnumerable<InMemoryScope>? scopes)
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (scopes is not null)
        {
            foreach (var scope in scopes)
            {
                builder.Services.AddSingleton(scope);
            }
        }

        return builder;
    }

    public static IOpenIdentityFrameworkBuilder<
            InMemoryRequestContext,
            InMemoryClient,
            InMemoryClientSecret,
            InMemoryScope,
            InMemoryResource,
            InMemoryResourceSecret,
            InMemoryAuthorizeRequestError,
            InMemoryResourceOwnerEssentialClaims,
            InMemoryResourceOwnerIdentifiers,
            InMemoryAuthorizeRequest,
            InMemoryAuthorizeRequestConsent,
            InMemoryGrantedConsent,
            InMemoryAuthorizationCode,
            InMemoryAccessToken,
            InMemoryRefreshToken>
        AddInMemorySigningCredentials(
            this IOpenIdentityFrameworkBuilder<
                InMemoryRequestContext,
                InMemoryClient,
                InMemoryClientSecret,
                InMemoryScope,
                InMemoryResource,
                InMemoryResourceSecret,
                InMemoryAuthorizeRequestError,
                InMemoryResourceOwnerEssentialClaims,
                InMemoryResourceOwnerIdentifiers,
                InMemoryAuthorizeRequest,
                InMemoryAuthorizeRequestConsent,
                InMemoryGrantedConsent,
                InMemoryAuthorizationCode,
                InMemoryAccessToken,
                InMemoryRefreshToken> builder,
            IEnumerable<SigningCredentials>? credentials)
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (credentials is not null)
        {
            foreach (var sign in credentials)
            {
                builder.Services.AddSingleton(sign);
            }
        }

        return builder;
    }
}
