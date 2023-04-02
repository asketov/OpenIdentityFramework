using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Endpoints.Handlers;
using OpenIdentityFramework.Endpoints.Handlers.Implementations;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Implementations;

namespace OpenIdentityFramework.Configuration.Builder;

public class OpenIdentityFrameworkBuilder : IOpenIdentityFrameworkBuilder
{
    public OpenIdentityFrameworkBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }

    public IOpenIdentityFrameworkBuilder AddRequiredPlatformServices()
    {
        Services.AddOptions<OpenIdentityFrameworkOptions>();
        Services.TryAddSingleton(static resolver => resolver.GetRequiredService<IOptions<OpenIdentityFrameworkOptions>>().Value);
        Services.AddHttpClient();
        Services.AddDataProtection();
        Services.AddAuthentication();
        return this;
    }

    public IOpenIdentityFrameworkBuilder AddCoreServices(Action<OpenIdentityFrameworkOptions>? configure = null)
    {
        Services.Configure<OpenIdentityFrameworkOptions>(frameworkOptions => configure?.Invoke(frameworkOptions));
        Services.TryAddSingleton<IIssuerUrlProvider, DefaultIssuerUrlProvider>();
        return this;
    }

    public IOpenIdentityFrameworkBuilder AddDefaultEndpointHandlers()
    {
        // -----------------------
        // ------ Authorize ------
        // -----------------------
        Services.TryAddSingleton<IAuthorizeEndpointHandler, DefaultAuthorizeEndpointHandler>();
        return this;
    }
}
