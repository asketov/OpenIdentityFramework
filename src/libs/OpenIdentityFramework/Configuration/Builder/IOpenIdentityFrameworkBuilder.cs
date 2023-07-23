using System;
using Microsoft.Extensions.DependencyInjection;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Configuration.Builder;

public interface IOpenIdentityFrameworkBuilder<
    TRequestContext,
    TClient,
    TClientSecret,
    TScope,
    TResource,
    TResourceSecret,
    TAuthorizeRequestError,
    TResourceOwnerEssentialClaims,
    TResourceOwnerIdentifiers,
    TAuthorizeRequest,
    TAuthorizeRequestConsent,
    TGrantedConsent,
    TAuthorizationCode,
    TAccessToken,
    TRefreshToken>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TAuthorizeRequestError : AbstractAuthorizeRequestError
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
    where TAuthorizeRequest : AbstractAuthorizeRequest
    where TAuthorizeRequestConsent : AbstractAuthorizeRequestConsent<TResourceOwnerIdentifiers>
    where TGrantedConsent : AbstractGrantedConsent
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TAccessToken : AbstractAccessToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
{
    IServiceCollection Services { get; }

    IOpenIdentityFrameworkBuilder<
        TRequestContext,
        TClient,
        TClientSecret,
        TScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestError,
        TResourceOwnerEssentialClaims,
        TResourceOwnerIdentifiers,
        TAuthorizeRequest,
        TAuthorizeRequestConsent,
        TGrantedConsent,
        TAuthorizationCode,
        TAccessToken,
        TRefreshToken> AddRequiredPlatformServices();

    IOpenIdentityFrameworkBuilder<
        TRequestContext,
        TClient,
        TClientSecret,
        TScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestError,
        TResourceOwnerEssentialClaims,
        TResourceOwnerIdentifiers,
        TAuthorizeRequest,
        TAuthorizeRequestConsent,
        TGrantedConsent,
        TAuthorizationCode,
        TAccessToken,
        TRefreshToken> AddCoreServices(Action<OpenIdentityFrameworkOptions>? configure = null);

    IOpenIdentityFrameworkBuilder<
        TRequestContext,
        TClient,
        TClientSecret,
        TScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestError,
        TResourceOwnerEssentialClaims,
        TResourceOwnerIdentifiers,
        TAuthorizeRequest,
        TAuthorizeRequestConsent,
        TGrantedConsent,
        TAuthorizationCode,
        TAccessToken,
        TRefreshToken> AddDefaultEndpointHandlers();
}
