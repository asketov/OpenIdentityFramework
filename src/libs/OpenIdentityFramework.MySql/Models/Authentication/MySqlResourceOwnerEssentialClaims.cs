using System;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.MySql.Models.Authentication;

public class MySqlResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<MySqlResourceOwnerIdentifiers>
{
    public MySqlResourceOwnerEssentialClaims(MySqlResourceOwnerIdentifiers resourceOwnerIdentifiers, DateTimeOffset authenticationDate)
    {
        ArgumentNullException.ThrowIfNull(resourceOwnerIdentifiers);

        ResourceOwnerIdentifiers = resourceOwnerIdentifiers;
        AuthenticationDate = authenticationDate;
    }

    public MySqlResourceOwnerIdentifiers ResourceOwnerIdentifiers { get; }
    public DateTimeOffset AuthenticationDate { get; }

    public override MySqlResourceOwnerIdentifiers GetResourceOwnerIdentifiers()
    {
        return ResourceOwnerIdentifiers;
    }

    public override DateTimeOffset GetAuthenticationDate()
    {
        return AuthenticationDate;
    }
}
