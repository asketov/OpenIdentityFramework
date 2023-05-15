using System;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.InMemory.Models.Authentication;

public class InMemoryResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<InMemoryResourceOwnerIdentifiers>
{
    public InMemoryResourceOwnerEssentialClaims(InMemoryResourceOwnerIdentifiers resourceOwnerIdentifiers, DateTimeOffset authenticationDate)
    {
        ArgumentNullException.ThrowIfNull(resourceOwnerIdentifiers);

        ResourceOwnerIdentifiers = resourceOwnerIdentifiers;
        AuthenticationDate = authenticationDate;
    }

    public InMemoryResourceOwnerIdentifiers ResourceOwnerIdentifiers { get; }
    public DateTimeOffset AuthenticationDate { get; }

    public override InMemoryResourceOwnerIdentifiers GetResourceOwnerIdentifiers()
    {
        return ResourceOwnerIdentifiers;
    }

    public override DateTimeOffset GetAuthenticationDate()
    {
        return AuthenticationDate;
    }
}
