using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.MySql.Services.Operation.ResourceOwnerEssentialClaimsProvider;

public class MySqlResourceOwnerEssentialClaimsProviderOptions
{
    public string SubjectIdClaimType { get; set; } = DefaultJwtClaimTypes.Subject;
    public string SessionIdIdClaimType { get; set; } = DefaultJwtClaimTypes.SessionId;
}
