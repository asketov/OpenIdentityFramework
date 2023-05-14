using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.MySql.Models.Authentication;

public class MySqlResourceOwnerIdentifiersEqualityComparer : IEqualityComparer<MySqlResourceOwnerIdentifiers>
{
    public bool Equals(MySqlResourceOwnerIdentifiers? x, MySqlResourceOwnerIdentifiers? y)
    {
        if (ReferenceEquals(x, y))
        {
            return true;
        }

        if (ReferenceEquals(x, null))
        {
            return false;
        }

        if (ReferenceEquals(y, null))
        {
            return false;
        }

        if (x.GetType() != y.GetType())
        {
            return false;
        }

        return x.SubjectId == y.SubjectId && x.SessionId == y.SessionId;
    }

    public int GetHashCode(MySqlResourceOwnerIdentifiers? obj)
    {
        return HashCode.Combine(obj?.SubjectId, obj?.SessionId);
    }
}
