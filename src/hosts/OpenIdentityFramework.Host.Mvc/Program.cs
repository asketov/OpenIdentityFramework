using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Configuration.DependencyInjection.Extensions;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Host.Mvc.Constants;
using OpenIdentityFramework.Host.Mvc.Services.Local;
using OpenIdentityFramework.Host.Mvc.Services.Local.Implementations.ClaimsPrincipalFactory;
using OpenIdentityFramework.Host.Mvc.Services.Local.Implementations.PasswordHasher;
using OpenIdentityFramework.Host.Mvc.Services.Local.Implementations.Users;
using OpenIdentityFramework.Host.Mvc.Services.Local.Models;
using OpenIdentityFramework.Host.Mvc.Services.OpenIdentityFramework;
using OpenIdentityFramework.InMemory.Configuration.DependencyInjection.Extensions;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.InMemory.Models.Configuration;
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Services.Static.Cryptography;

namespace OpenIdentityFramework.Host.Mvc;

[SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
public sealed class Program
{
    public static void Main(string[] args)
    {
        var app = CreateWebApplicationBuilder(args).Build();
        app.UseHttpsRedirection();
        app.UseCookiePolicy(); // <-- same-site None fix
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Home/Error");
            app.UseHsts();
        }

        app.UseStaticFiles();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapOpenIdentityFrameworkEndpoints<InMemoryRequestContext>(); // <-- call after UseAuthentication
        app.MapDefaultControllerRoute();
        app.Run();
    }

    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    internal static WebApplicationBuilder CreateWebApplicationBuilder(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        // Add default MVC services to the container.
        builder.Services.AddControllersWithViews(options => options.EnableEndpointRouting = true);
        builder.Services.Configure<RouteOptions>(options =>
        {
            options.LowercaseUrls = true;
            options.AppendTrailingSlash = false;
            options.LowercaseQueryStrings = false; // <-- important!
        });

        // Add local infrastructure to work with users and sign-in
        builder.Services.AddSingleton<ILocalUserService, LocalUserService>();
        builder.Services.Configure<LocalUserClaimsPrincipalPrincipalFactoryOptions>(options =>
        {
            options.AuthenticationType = LocalAuthenticationSchemes.Cookies;
            options.NameClaimType = LocalUserClaimTypes.Login;
            options.RoleClaimType = LocalUserClaimTypes.Role;
        });
        builder.Services.AddSingleton<ILocalUserClaimsPrincipalFactory, LocalUserClaimsPrincipalPrincipalFactory>();
        builder.Services.AddSingleton<ILocalUserPasswordHasher, LocalUserPasswordHasher>();
        foreach (var localUser in GetLocalUsers())
        {
            builder.Services.AddSingleton(localUser);
        }

        // OpenIdentityFramework - related services and configuration
        // Add authentication
        builder.Services.AddDataProtection(options =>
        {
            options.ApplicationDiscriminator = "open-identity-framework-mvc";
        });
        builder.Services.AddAuthentication(LocalAuthenticationSchemes.Cookies)
            .AddCookie(LocalAuthenticationSchemes.Cookies, options =>
            {
                options.LoginPath = "/account/login";
                options.LogoutPath = "/account/logout";
                options.AccessDeniedPath = "/error";
                options.ReturnUrlParameter = "returnUrl";
            });
        // Configure server-side sessions
        builder.Services.ConfigureCookieAuthenticationServerSideStorage(LocalAuthenticationSchemes.Cookies);
        // SameSite=None is sometimes interpreted as SameSite=Strict, fix for that
        builder.Services.ConfigureSameSiteNoneCookiePolicy();
        // OpenIdentityFramework services
        builder.Services.AddInMemoryOpenIdentityFrameworkBuilder(options =>
            {
                options.UserInteraction.LoginUrl = "/account/login";
                options.ErrorHandling.HideErrorDescriptionsOnSafeAuthorizeErrorResponses = false;
            })
            .AddInMemoryStorages(options =>
            {
                options.DefaultServerSessionDuration = TimeSpan.FromHours(1);
            })
            .AddInMemoryServices(options =>
            {
                options.SubjectIdClaimType = LocalUserClaimTypes.UserId;
                options.SessionIdIdClaimType = LocalUserClaimTypes.SessionId;
            })
            .AddInMemoryClients(GetClients())
            .AddInMemoryScopes(GetScopes())
            .AddInMemoryResources(GetResources())
            .AddInMemorySigningCredentials(GetSigningCredentials());
        // Profile
        builder.Services.TryAddSingleton<
            IUserProfileService<InMemoryRequestContext, InMemoryResourceOwnerIdentifiers>,
            LocalUserProfileService<InMemoryRequestContext, InMemoryResourceOwnerIdentifiers>>();
        return builder;
    }

    private static IReadOnlyCollection<InMemoryClient> GetClients()
    {
        return new[]
        {
            InMemoryClient.ClientCredentials(
                "client_creds",
                "client_creds_secret",
                DateTimeOffset.UtcNow,
                new HashSet<string>
                {
                    "api_scope1"
                }),
            InMemoryClient.AuthorizationCode(
                "authz_code",
                "client_authz_code_secret",
                DateTimeOffset.UtcNow,
                new HashSet<string>
                {
                    DefaultScopes.OpenId,
                    DefaultScopes.OfflineAccess,
                    "api_scope1"
                },
                new[] { new Uri("https://localhost:5000/signin-oidc") })
        };
    }

    private static IReadOnlyCollection<InMemoryResource> GetResources()
    {
        return new[]
        {
            InMemoryResource.Create("api1", "api1_secret", DateTimeOffset.UtcNow, new HashSet<string>
            {
                "api_scope1"
            })
        };
    }

    private static IReadOnlyCollection<InMemoryScope> GetScopes()
    {
        return new[]
        {
            new InMemoryScope(
                "api_scope1",
                DefaultTokenTypes.AccessToken,
                true,
                true,
                new HashSet<string>(StringComparer.Ordinal)),
            new InMemoryScope(
                "openid",
                DefaultTokenTypes.IdToken,
                true,
                true,
                new HashSet<string>(StringComparer.Ordinal)
                {
                    DefaultJwtClaimTypes.Subject
                })
        };
    }

    private static IReadOnlyCollection<SigningCredentials> GetSigningCredentials()
    {
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
        var credentials = new SigningCredentials(jwk, SecurityAlgorithms.RsaSha256);
        return new[] { credentials };
    }

    private static IReadOnlyCollection<LocalUser> GetLocalUsers()
    {
        return new LocalUser[]
        {
            new(
                new("B38BEDAA-4CC5-451B-A4AA-E356113BFEF9"),
                "bob",
                LocalUserPasswordHasher.Instance.ComputeHash("bob"),
                new HashSet<string>
                {
                    LocalUserRoles.Admin,
                    LocalUserRoles.Moderator,
                    LocalUserRoles.User
                }),
            new(
                new("E0D0C397-A7E2-4A92-B259-6B17D4B241C1"),
                "alice",
                LocalUserPasswordHasher.Instance.ComputeHash("alice"),
                new HashSet<string>
                {
                    LocalUserRoles.User
                })
        };
    }
}
