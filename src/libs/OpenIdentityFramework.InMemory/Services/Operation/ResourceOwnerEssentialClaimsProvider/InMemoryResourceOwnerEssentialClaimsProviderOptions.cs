using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.InMemory.Services.Operation.ResourceOwnerEssentialClaimsProvider;

public class InMemoryResourceOwnerEssentialClaimsProviderOptions
{
    public string SubjectIdClaimType { get; set; } = DefaultJwtClaimTypes.Subject;
    public string SessionIdIdClaimType { get; set; } = DefaultJwtClaimTypes.SessionId;
}
