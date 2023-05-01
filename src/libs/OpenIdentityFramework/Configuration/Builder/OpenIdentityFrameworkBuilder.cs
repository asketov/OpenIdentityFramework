using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Implementations;

namespace OpenIdentityFramework.Configuration.Builder;

public class OpenIdentityFrameworkBuilder<TRequestContext>
    : IOpenIdentityFrameworkBuilder<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    public OpenIdentityFrameworkBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }

    public IOpenIdentityFrameworkBuilder<TRequestContext> AddRequiredPlatformServices()
    {
        Services.AddOptions<OpenIdentityFrameworkOptions>();
        Services.TryAddSingleton(static resolver => resolver.GetRequiredService<IOptions<OpenIdentityFrameworkOptions>>().Value);
        Services.AddHttpClient();
        Services.AddDataProtection();
        Services.AddAuthentication();
        return this;
    }

    public IOpenIdentityFrameworkBuilder<TRequestContext> AddCoreServices(Action<OpenIdentityFrameworkOptions>? configure = null)
    {
        Services.Configure<OpenIdentityFrameworkOptions>(frameworkOptions => configure?.Invoke(frameworkOptions));
        Services.TryAddSingleton<IIssuerUrlProvider<TRequestContext>, DefaultIssuerUrlProvider<TRequestContext>>();
        return this;
    }

    public IOpenIdentityFrameworkBuilder<TRequestContext> AddDefaultEndpointHandlers()
    {
        // -----------------------
        // ------ Authorize ------
        // -----------------------
        //Services.TryAddSingleton<IAuthorizeEndpointHandler, DefaultAuthorizeEndpointHandler>();
        return this;
    }
}
