using System;
using Microsoft.Extensions.DependencyInjection;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Configuration.Builder;

public interface IOpenIdentityFrameworkBuilder<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    IServiceCollection Services { get; }
    IOpenIdentityFrameworkBuilder<TRequestContext> AddRequiredPlatformServices();
    IOpenIdentityFrameworkBuilder<TRequestContext> AddCoreServices(Action<OpenIdentityFrameworkOptions>? configure = null);
    IOpenIdentityFrameworkBuilder<TRequestContext> AddDefaultEndpointHandlers();
}
