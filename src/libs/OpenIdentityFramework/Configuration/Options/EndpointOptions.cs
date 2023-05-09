using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Configuration.Options.Endpoints;

namespace OpenIdentityFramework.Configuration.Options;

[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
[SuppressMessage("ReSharper", "IdentifierTypo")]
public class EndpointOptions
{
    public AuthorizeEndpointOptions Authorize { get; set; } = new();
    public TokenEndpointOptions Token { get; set; } = new();
    public DiscoveryEndpointOptions Discovery { get; set; } = new();
    public JwksEndpointOptions Jwks { get; set; } = new();
    public UserInfoEndpointOptions UserInfo { get; set; } = new();
}
