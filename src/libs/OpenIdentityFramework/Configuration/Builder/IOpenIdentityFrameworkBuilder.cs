using System;
using Microsoft.Extensions.DependencyInjection;
using OpenIdentityFramework.Configuration.Options;

namespace OpenIdentityFramework.Configuration.Builder;

public interface IOpenIdentityFrameworkBuilder
{
    IServiceCollection Services { get; }
    IOpenIdentityFrameworkBuilder AddRequiredPlatformServices();
    IOpenIdentityFrameworkBuilder AddCoreServices(Action<OpenIdentityFrameworkOptions>? configure = null);
    IOpenIdentityFrameworkBuilder AddDefaultEndpointHandlers();
}
