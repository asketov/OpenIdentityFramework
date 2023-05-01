using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options;

public class AuthenticationOptions
{
    public string? AuthenticationScheme { get; set; }
    public string SubjectIdClaimType { get; set; } = DefaultJwtClaimTypes.Subject;
    public string SessionIdClaimType { get; set; } = DefaultJwtClaimTypes.SessionId;
}
