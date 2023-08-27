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

    protected InMemoryResourceOwnerIdentifiers ResourceOwnerIdentifiers { get; }
    protected DateTimeOffset AuthenticationDate { get; }

    public override InMemoryResourceOwnerIdentifiers GetResourceOwnerIdentifiers()
    {
        return ResourceOwnerIdentifiers;
    }

    public override DateTimeOffset GetAuthenticationDate()
    {
        return AuthenticationDate;
    }
}
