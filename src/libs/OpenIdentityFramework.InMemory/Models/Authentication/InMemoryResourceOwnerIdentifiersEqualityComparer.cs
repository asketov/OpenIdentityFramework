using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.InMemory.Models.Authentication;

public class InMemoryResourceOwnerIdentifiersEqualityComparer : IEqualityComparer<InMemoryResourceOwnerIdentifiers>
{
    public bool Equals(InMemoryResourceOwnerIdentifiers? x, InMemoryResourceOwnerIdentifiers? y)
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

        return x.GetSubjectId() == y.GetSubjectId() && x.GetSessionId() == y.GetSessionId();
    }

    public int GetHashCode(InMemoryResourceOwnerIdentifiers? obj)
    {
        return HashCode.Combine(obj?.GetSubjectId(), obj?.GetSessionId());
    }
}
