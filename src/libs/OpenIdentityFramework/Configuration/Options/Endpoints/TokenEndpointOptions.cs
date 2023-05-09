using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options.Endpoints;

public class TokenEndpointOptions
{
    public string Path { get; set; } = DefaultRoutes.Token;
}
