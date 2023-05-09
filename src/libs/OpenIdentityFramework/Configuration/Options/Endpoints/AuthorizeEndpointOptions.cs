using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options.Endpoints;

[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class AuthorizeEndpointOptions
{
    public string Path { get; set; } = DefaultRoutes.Authorize;
    public string CallbackPath { get; set; } = DefaultRoutes.AuthorizeCallback;

    public TimeSpan? AuthorizeRequestLifetime { get; set; } = TimeSpan.FromHours(1);
}
