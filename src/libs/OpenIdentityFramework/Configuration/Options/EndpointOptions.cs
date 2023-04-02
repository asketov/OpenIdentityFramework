using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Configuration.Options.Endpoints;

namespace OpenIdentityFramework.Configuration.Options;

[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class EndpointOptions
{
    public AuthorizeEndpointOptions Authorize { get; set; } = new();
}
