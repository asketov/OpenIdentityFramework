using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options.Endpoints;

[SuppressMessage("ReSharper", "IdentifierTypo")]
public class JwksEndpointOptions
{
    public string Path { get; set; } = DefaultRoutes.Jwks;
}
