using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options.Endpoints;

[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class DiscoveryEndpointOptions
{
    public bool Enable { get; set; } = true;
    public string Path { get; set; } = DefaultRoutes.Discovery;
    public TimeSpan? ResponseHttpCacheInterval { get; set; }
    public TimeSpan? DiscoveryDocumentInMemoryCacheInterval { get; set; } = TimeSpan.FromMinutes(1);
    public bool ShowScopesSupported { get; set; } = true;
    public bool ShowResponseModesSupported { get; set; } = true;
    public bool ShowGrantTypesSupported { get; set; } = true;
    public bool ShowTokenEndpointAuthMethodsSupported { get; set; } = true;
    public bool ShowDisplayValuesSupported { get; set; } = true;
    public bool ShowClaimsSupported { get; set; } = true;
}
