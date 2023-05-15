using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.InMemory.Services.Operation.ResourceOwnerEssentialClaimsFactory;

public class InMemoryResourceOwnerEssentialClaimsFactoryOptions
{
    public string SubjectIdClaimType { get; set; } = DefaultJwtClaimTypes.Subject;
    public string SessionIdIdClaimType { get; set; } = DefaultJwtClaimTypes.SessionId;
}
