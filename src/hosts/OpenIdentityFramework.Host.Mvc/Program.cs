using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Configuration.DependencyInjection.Extensions;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Endpoints.Handlers;
using OpenIdentityFramework.Endpoints.Handlers.Implementations;
using OpenIdentityFramework.Host.Mvc.Services;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.InMemory.Models.Configuration;
using OpenIdentityFramework.InMemory.Models.Operation;
using OpenIdentityFramework.InMemory.Services.Operation.RequestContextFactory;
using OpenIdentityFramework.InMemory.Services.Operation.ResourceOwnerEssentialClaimsFactory;
using OpenIdentityFramework.InMemory.Storages.Configuration;
using OpenIdentityFramework.InMemory.Storages.Operation;
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
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Services.Static.Cryptography;
using OpenIdentityFramework.Storages.Configuration;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Host.Mvc;

[SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
public sealed class Program
{
    public static void Main(string[] args)
    {
        var app = CreateWebApplicationBuilder(args).Build();
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Home/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseCookiePolicy(); // <-- same-site None fix
        app.UseStaticFiles();
        app.UseRouting();
        app.UseAuthentication();
        app.MapOpenIdentityFrameworkEndpoints<InMemoryRequestContext>(); // <-- call after UseAuthentication
        app.UseAuthorization();
        app.MapDefaultControllerRoute();
        app.Run();
    }

    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    internal static WebApplicationBuilder CreateWebApplicationBuilder(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        // Add services to the container.
        builder.Services.AddControllersWithViews(options => options.EnableEndpointRouting = true);
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
        builder.Services.Configure<RouteOptions>(options =>
        {
            options.LowercaseUrls = true;
            options.AppendTrailingSlash = false;
            options.LowercaseQueryStrings = false; // <-- important!
        });
        builder.Services.ConfigureSameSiteNoneCookiePolicy();
        AddOpenIdentityFramework<
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
            InMemoryRefreshToken>(builder.Services);

        // Profile
        builder.Services.TryAddSingleton<
            IUserProfileService<InMemoryRequestContext, InMemoryResourceOwnerIdentifiers>,
            LocalUserProfileService<InMemoryRequestContext, InMemoryResourceOwnerIdentifiers>>();
        AddInMemoryServices(builder.Services);
        AddInMemoryStorages(builder.Services);
        AdInMemoryConfiguration(builder.Services);
        return builder;
    }

    private static void AddInMemoryServices(IServiceCollection services)
    {
        services.TryAddSingleton<
            IEqualityComparer<InMemoryResourceOwnerIdentifiers>,
            InMemoryResourceOwnerIdentifiersEqualityComparer>();
        services.TryAddSingleton<
            IRequestContextFactory<InMemoryRequestContext>,
            InMemoryRequestContextFactory>();
        services.TryAddSingleton<
            IResourceOwnerEssentialClaimsFactory<InMemoryRequestContext, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>,
            InMemoryResourceOwnerEssentialClaimsFactory>();
        services.AddOptions<InMemoryResourceOwnerEssentialClaimsFactoryOptions>();
    }

    private static void AddInMemoryStorages(IServiceCollection services)
    {
        // Operation
        services.TryAddSingleton<
            IAccessTokenStorage<InMemoryRequestContext, InMemoryAccessToken, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>,
            InMemoryAccessTokenStorage>();
        services.TryAddSingleton<
            IAuthorizationCodeStorage<InMemoryRequestContext, InMemoryAuthorizationCode, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>,
            InMemoryAuthorizationCodeStorage>();
        services.TryAddSingleton<
            IAuthorizeRequestConsentStorage<InMemoryRequestContext, InMemoryAuthorizeRequestConsent, InMemoryResourceOwnerIdentifiers>,
            InMemoryAuthorizeRequestConsentStorage>();
        services.TryAddSingleton<
            IAuthorizeRequestErrorStorage<InMemoryRequestContext, InMemoryAuthorizeRequestError>,
            InMemoryAuthorizeRequestErrorStorage>();
        services.TryAddSingleton<
            IAuthorizeRequestStorage<InMemoryRequestContext, InMemoryAuthorizeRequest>,
            InMemoryAuthorizeRequestStorage>();
        services.TryAddSingleton<
            IGrantedConsentStorage<InMemoryRequestContext, InMemoryGrantedConsent>,
            InMemoryGrantedConsentStorage>();
        services.TryAddSingleton<
            IRefreshTokenStorage<InMemoryRequestContext, InMemoryRefreshToken, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>,
            InMemoryRefreshTokenStorage>();

        // Configuration
        services.TryAddSingleton<
            IClientStorage<InMemoryRequestContext, InMemoryClient, InMemoryClientSecret>,
            InMemoryClientStorage>();
        services.TryAddSingleton<
            IKeyMaterialStorage<InMemoryRequestContext>,
            InMemoryKeyMaterialStorage>();
        services.TryAddSingleton<
            IResourceStorage<InMemoryRequestContext, InMemoryScope, InMemoryResource, InMemoryResourceSecret>,
            InMemoryResourceStorage>();
    }

    private static void AdInMemoryConfiguration(IServiceCollection services)
    {
        services.AddSingleton(new InMemoryClient(
            "client_creds",
            new HashSet<string>(),
            DefaultClientTypes.Confidential,
            new HashSet<string>
            {
                "api_scope1"
            },
            new HashSet<string>
            {
                DefaultAuthorizationFlows.ClientCredentials
            },
            new HashSet<string>(),
            false,
            false,
            null,
            TimeSpan.FromMinutes(5),
            true,
            true,
            new HashSet<string>(),
            new HashSet<string>(),
            TimeSpan.FromMinutes(5),
            DefaultClientAuthenticationMethods.ClientSecretPost,
            new HashSet<InMemoryClientSecret>
            {
                new(DefaultSecretTypes.PreSharedSecret, DefaultClientSecretHasher.Instance.ComputeHash("secret"), null)
            },
            DefaultAccessTokenFormat.Jwt,
            true,
            TimeSpan.FromHours(1),
            TimeSpan.Zero,
            TimeSpan.FromHours(3),
            DefaultRefreshTokenExpirationType.Sliding));
        services.AddSingleton(new InMemoryResource(
            "api1",
            new HashSet<string>
            {
                "api_scope1"
            },
            new HashSet<InMemoryResourceSecret>
            {
                new(DefaultSecretTypes.PreSharedSecret, DefaultClientSecretHasher.Instance.ComputeHash("secret"), null)
            }));
        services.AddSingleton(new InMemoryScope(
            "api_scope1",
            DefaultTokenTypes.AccessToken,
            true,
            true,
            new HashSet<string>()));
#pragma warning disable CA2000
        var rsaKey = RSA.Create(2048);
#pragma warning restore CA2000
        var key = new RsaSecurityKey(rsaKey)
        {
            KeyId = CryptoRandom.Create(16)
        };
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.Alg = SecurityAlgorithms.RsaSha256;
        jwk.Use = "sig";
        services.AddSingleton(new SigningCredentials(jwk, SecurityAlgorithms.RsaSha256));
    }

    private static void AddOpenIdentityFramework<
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
        TRefreshToken>(IServiceCollection services)
        where TRequestContext : class, IRequestContext
        where TClient : AbstractClient<TClientSecret>
        where TClientSecret : AbstractSecret
        where TScope : AbstractScope
        where TResource : AbstractResource<TResourceSecret>
        where TResourceSecret : AbstractSecret
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
        // AddRequiredPlatformServices
        services.AddOptions<OpenIdentityFrameworkOptions>();
        services.TryAddSingleton(static resolver => resolver.GetRequiredService<IOptions<OpenIdentityFrameworkOptions>>().Value);
        services.AddHttpClient();
        services.AddDataProtection();
        services.AddAuthentication();
        services.AddMemoryCache();

        // AddCoreServices
        services.TryAddSingleton<
            IIssuerUrlProvider<TRequestContext>,
            DefaultIssuerUrlProvider<TRequestContext>>();
        services.TryAddSingleton<
            IClientService<TRequestContext, TClient, TClientSecret>,
            DefaultClientService<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IResourceService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultResourceService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        services.TryAddSingleton<
            IResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            IResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            IGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent>,
            DefaultGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent>>();
        services.TryAddSingleton<
            IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            IKeyMaterialService<TRequestContext>,
            DefaultKeyMaterialService<TRequestContext>>();
        services.TryAddSingleton<
            IIdTokenLeftMostHasher,
            DefaultIdTokenLeftMostHasher>();
        services.TryAddSingleton<
            IJwtService<TRequestContext>,
            DefaultJwtService<TRequestContext>>();
        services.TryAddSingleton<
            IClientAuthenticationService<TRequestContext, TClient, TClientSecret>,
            DefaultClientAuthenticationService<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IClientSecretHasher,
            DefaultClientSecretHasher>();
        services.TryAddSingleton<
            IClientSecretValidator<TRequestContext, TClient, TClientSecret>,
            DefaultClientSecretValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();

        // AuthorizeEndpoint
        services.TryAddSingleton<
            IAuthorizeEndpointHandler<TRequestContext>,
            DefaultAuthorizeEndpointHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestError, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizeRequest, TAuthorizeRequestConsent>>();
        services.TryAddSingleton<
            IAuthorizeEndpointCallbackHandler<TRequestContext>,
            DefaultAuthorizeEndpointCallbackHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestError, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizeRequest, TAuthorizeRequestConsent>>();
        services.TryAddSingleton<
            IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestParameterClientIdValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterClientIdValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<IAuthorizeRequestParameterResponseTypeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterResponseTypeValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestParameterStateValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterStateValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultAuthorizeRequestParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestParameterCodeChallengeMethodValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterCodeChallengeMethodValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestParameterCodeChallengeValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterNonceValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterNonceValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterPromptValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterPromptValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterMaxAgeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterMaxAgeValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterLoginHintValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterLoginHintValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterAcrValuesValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterAcrValuesValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterDisplayValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterDisplayValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterUiLocalesValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterUiLocalesValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterRequestValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterRequestValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterRequestUriValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterRequestUriValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestOidcParameterRegistrationValidator<TRequestContext, TClient, TClientSecret>,
            DefaultAuthorizeRequestOidcParameterRegistrationValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            IAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError>,
            DefaultAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError>>();
        services.TryAddSingleton<
            IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestConsent, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizeRequestConsent, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TGrantedConsent>>();
        services.TryAddSingleton<
            IAuthorizeRequestConsentService<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers>,
            DefaultAuthorizeRequestConsentService<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            IAuthorizeRequestService<TRequestContext, TAuthorizeRequest>,
            DefaultAuthorizeRequestService<TRequestContext, TAuthorizeRequest>>();
        services.TryAddSingleton<
            IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizationCode>>();


        // Discovery
        services.TryAddSingleton<
            IDiscoveryEndpointHandler<TRequestContext>,
            DefaultDiscoveryEndpointHandler<TRequestContext>>();
        services.TryAddSingleton<
            IDiscoveryResponseGenerator<TRequestContext>,
            DefaultDiscoveryResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();

        // Jwks
        services.TryAddSingleton<
            IJwksEndpointHandler<TRequestContext>,
            DefaultJwksEndpointHandler<TRequestContext>>();
        services.TryAddSingleton<
            IJwksResponseGenerator<TRequestContext>,
            DefaultJwksResponseGenerator<TRequestContext>>();

        // Token
        services.TryAddSingleton<
            ITokenEndpointHandler<TRequestContext>,
            DefaultTokenEndpointHandler<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAuthorizationCode, TRefreshToken>>();
        services.TryAddSingleton<
            ITokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            ITokenRequestCommonParameterGrantTypeValidator<TRequestContext, TClient, TClientSecret>,
            DefaultTokenRequestCommonParameterGrantTypeValidator<TRequestContext, TClient, TClientSecret>>();
        services.TryAddSingleton<
            ITokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TGrantedConsent>>();
        services.TryAddSingleton<
            ITokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            ITokenRequestAuthorizationCodeParameterCodeVerifierValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestAuthorizationCodeParameterCodeVerifierValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            ITokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            ITokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultTokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        services.TryAddSingleton<
            ITokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>,
            DefaultTokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>>();
        services.TryAddSingleton<
            ITokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TGrantedConsent>>();
        services.TryAddSingleton<
            ITokenRequestRefreshTokenParameterRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenRequestRefreshTokenParameterRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        services.TryAddSingleton<
            ITokenResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>,
            DefaultTokenResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers, TAccessToken>>();
    }
}
