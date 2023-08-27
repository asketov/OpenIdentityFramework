using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Endpoints.Handlers;
using OpenIdentityFramework.Endpoints.Handlers.Implementations;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Implementations;
using OpenIdentityFramework.Services.Cryptography;
using OpenIdentityFramework.Services.Cryptography.Implementations;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;
using OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;
using OpenIdentityFramework.Services.Endpoints.Discovery;
using OpenIdentityFramework.Services.Endpoints.Discovery.Implementations;
using OpenIdentityFramework.Services.Endpoints.Jwks;
using OpenIdentityFramework.Services.Endpoints.Jwks.Implementations;
using OpenIdentityFramework.Services.Endpoints.Token;
using OpenIdentityFramework.Services.Endpoints.Token.Implementations;
using OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation;
using OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.CommonParameters;
using OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.AuthorizationCode;
using OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.AuthorizationCode.Parameters;
using OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.ClientCredentials;
using OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.RefreshToken;
using OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.RefreshToken.Parameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.CommonParameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode.Parameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.ClientCredentials;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.RefreshToken;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.RefreshToken.Parameters;
using OpenIdentityFramework.Services.Integration.Implementations;

namespace OpenIdentityFramework.Configuration.Builder;

public class OpenIdentityFrameworkBuilder<
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
    : IOpenIdentityFrameworkBuilder<
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
    public OpenIdentityFrameworkBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }

    public IOpenIdentityFrameworkBuilder<
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
        TRefreshToken> AddRequiredPlatformServices()
    {
        // AddRequiredPlatformServices
        Services.AddOptions<OpenIdentityFrameworkOptions>();
        Services.TryAddSingleton(static resolver => resolver.GetRequiredService<IOptions<OpenIdentityFrameworkOptions>>().Value);
        Services.AddHttpClient();
        Services.AddDataProtection();
        Services.AddAuthentication();
        Services.TryAddSingleton<
            ITicketStore,
            OpenIdentityFrameworkTicketStore<TRequestContext>>();
        Services.TryAddSingleton<
            IResourceOwnerServerSessionService<TRequestContext>,
            DefaultResourceOwnerServerSessionService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.AddMemoryCache();
        return this;
    }

    public IOpenIdentityFrameworkBuilder<
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
        TRefreshToken> AddCoreServices(Action<OpenIdentityFrameworkOptions>? configure = null)
    {
        Services.Configure<OpenIdentityFrameworkOptions>(frameworkOptions => configure?.Invoke(frameworkOptions));
        Services.TryAddSingleton<
            IIssuerUrlProvider<TRequestContext>,
            DefaultIssuerUrlProvider<TRequestContext>>();
        Services.TryAddSingleton<
            IClientService<TRequestContext, TClient, TClientSecret>,
            DefaultClientService<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IResourceService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultResourceService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        Services.TryAddSingleton<
            IResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            IResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            IGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent>,
            DefaultGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent>>();
        Services.TryAddSingleton<
            IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            IKeyMaterialService<TRequestContext>,
            DefaultKeyMaterialService<TRequestContext>>();
        Services.TryAddSingleton<
            IIdTokenLeftMostHasher,
            DefaultIdTokenLeftMostHasher>();
        Services.TryAddSingleton<
            IJwtService<TRequestContext>,
            DefaultJwtService<TRequestContext>>();
        Services.TryAddSingleton<
            IClientAuthenticationService<TRequestContext, TClient, TClientSecret>,
            DefaultClientAuthenticationService<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IClientSecretHasher,
            DefaultClientSecretHasher>();
        Services.TryAddSingleton<
            IClientSecretValidator<TRequestContext, TClient, TClientSecret>,
            DefaultClientSecretValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        return this;
    }

    public IOpenIdentityFrameworkBuilder<
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
        TRefreshToken> AddDefaultEndpointHandlers()
    {
        // AuthorizeEndpoint
        Services.TryAddSingleton<
            IAuthorizeEndpointHandler<TRequestContext>,
            DefaultAuthorizeEndpointHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestError, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizeRequest, TAuthorizeRequestConsent>>();
        Services.TryAddSingleton<
            IAuthorizeEndpointCallbackHandler<TRequestContext>,
            DefaultAuthorizeEndpointCallbackHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestError, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizeRequest, TAuthorizeRequestConsent>>();
        Services.TryAddSingleton<
            IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestParameterClientIdValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterClientIdValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<IAuthorizeRequestParameterResponseTypeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterResponseTypeValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestParameterStateValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterStateValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultAuthorizeRequestParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestParameterCodeChallengeMethodValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterCodeChallengeMethodValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterNonceValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterNonceValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterPromptValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterPromptValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterMaxAgeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterMaxAgeValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterLoginHintValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterLoginHintValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterAcrValuesValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterAcrValuesValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterDisplayValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterDisplayValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterUiLocalesValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterUiLocalesValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterRequestValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterRequestValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterRequestUriValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterRequestUriValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestOidcParameterRegistrationValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterRegistrationValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            IAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError>,
            DefaultAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError>>();
        Services.TryAddSingleton<
            IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestConsent, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestConsent, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TGrantedConsent>>();
        Services.TryAddSingleton<
            IAuthorizeRequestConsentService<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers>,
            DefaultAuthorizeRequestConsentService<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            IAuthorizeRequestService<TRequestContext, TAuthorizeRequest>,
            DefaultAuthorizeRequestService<TRequestContext, TAuthorizeRequest>>();
        Services.TryAddSingleton<
            IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizationCode>>();

        // Discovery
        Services.TryAddSingleton<
            IDiscoveryEndpointHandler<TRequestContext>,
            DefaultDiscoveryEndpointHandler<TRequestContext>>();
        Services.TryAddSingleton<
            IDiscoveryResponseGenerator<TRequestContext>,
            DefaultDiscoveryResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();

        // Jwks
        Services.TryAddSingleton<
            IJwksEndpointHandler<TRequestContext>,
            DefaultJwksEndpointHandler<TRequestContext>>();
        Services.TryAddSingleton<
            IJwksResponseGenerator<TRequestContext>,
            DefaultJwksResponseGenerator<TRequestContext>>();

        // Token
        Services.TryAddSingleton<
            ITokenEndpointHandler<TRequestContext>,
            DefaultTokenEndpointHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizationCode, TRefreshToken>>();
        Services.TryAddSingleton<
            ITokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            ITokenRequestCommonParameterGrantTypeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultTokenRequestCommonParameterGrantTypeValidator<TRequestContext, TClient, TClientSecret>>();
        Services.TryAddSingleton<
            ITokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TGrantedConsent>>();
        Services.TryAddSingleton<
            ITokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            ITokenRequestAuthorizationCodeParameterCodeVerifierValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestAuthorizationCodeParameterCodeVerifierValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            ITokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            ITokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultTokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        Services.TryAddSingleton<
            ITokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultTokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        Services.TryAddSingleton<
            ITokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TGrantedConsent>>();
        Services.TryAddSingleton<
            ITokenRequestRefreshTokenParameterRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestRefreshTokenParameterRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        Services.TryAddSingleton<
            ITokenResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAccessToken>>();
        return this;
    }
}
