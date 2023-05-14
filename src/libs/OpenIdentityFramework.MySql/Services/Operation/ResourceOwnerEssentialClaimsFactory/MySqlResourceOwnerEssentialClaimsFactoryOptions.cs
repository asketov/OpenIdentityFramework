using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.MySql.Services.Operation.ResourceOwnerEssentialClaimsFactory;

public class MySqlResourceOwnerEssentialClaimsFactoryOptions
{
    public string SubjectIdClaimType { get; set; } = DefaultJwtClaimTypes.Subject;
    public string SessionIdIdClaimType { get; set; } = DefaultJwtClaimTypes.SessionId;
}
