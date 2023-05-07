using System;

namespace OpenIdentityFramework.Models.Authentication;

public class EssentialResourceOwnerClaims
{
    public EssentialResourceOwnerClaims(ResourceOwnerIdentifiers identifiers, DateTimeOffset authenticatedAt)
    {
        ArgumentNullException.ThrowIfNull(identifiers);
        Identifiers = identifiers;
        AuthenticatedAt = authenticatedAt;
    }

    public ResourceOwnerIdentifiers Identifiers { get; }

    public DateTimeOffset AuthenticatedAt { get; }
}
