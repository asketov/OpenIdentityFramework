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
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Configuration.DependencyInjection.Extensions;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Host.Mvc.Services;
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
        builder.Services.AddInMemoryOpenIdentityFrameworkBuilder()
            .AddInMemoryStorages()
            .AddInMemoryServices()
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
            InMemoryClient.ClientCredentials("client_creds", "client_creds_secret", DateTimeOffset.UtcNow, new HashSet<string>
            {
                "api_scope1"
            })
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
                new HashSet<string>())
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
}
