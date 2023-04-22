using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options;

public class AuthenticationOptions
{
    public string? AuthenticationScheme { get; set; }
    public string SubjectIdClaimType { get; set; } = DefaultClaimTypes.SubjectId;
    public string SessionIdClaimType { get; set; } = DefaultClaimTypes.SessionId;
}
