using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options.Endpoints;

public class UserInfoEndpointOptions
{
    public bool Enable { get; set; } = true;
    public string Path { get; set; } = DefaultRoutes.UserInfo;
}
