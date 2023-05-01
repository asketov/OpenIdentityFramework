using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options.Endpoints;

public class TokenEndpointOptions
{
    public bool Enable { get; set; } = true;
    public string Path { get; set; } = DefaultRoutes.Token;
}
