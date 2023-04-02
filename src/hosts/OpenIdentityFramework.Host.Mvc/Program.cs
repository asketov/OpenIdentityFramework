using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIdentityFramework.Configuration.DependencyInjection.Extensions;

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
        app.MapOpenIdentityFrameworkEndpoints(); // <-- call after UseAuthentication
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
        builder.Services.AddOpenIdentityFrameworkBuilder();
        builder.Services.ConfigureSameSiteNoneCookiePolicy();
        return builder;
    }
}
