using System;

namespace OpenIdentityFramework.Models.Authentication;

public abstract class AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public abstract TResourceOwnerIdentifiers GetResourceOwnerIdentifiers();
    public abstract DateTimeOffset GetAuthenticationDate();
}
