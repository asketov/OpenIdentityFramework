using System;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.InMemory.Models.Configuration;

public class InMemoryClientSecret : AbstractClientSecret, IEquatable<InMemoryClientSecret>
{
    private readonly long _expirationDate;
    private readonly byte[] _hashedValue;
    private readonly long _issueDate;

    public InMemoryClientSecret(byte[] hashedValue, long issueDate, long expirationDate)
    {
        ArgumentNullException.ThrowIfNull(hashedValue);
        _hashedValue = hashedValue;
        _issueDate = issueDate;
        _expirationDate = expirationDate;
    }

    public bool Equals(InMemoryClientSecret? other)
    {
        if (ReferenceEquals(null, other))
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return (ReferenceEquals(_hashedValue, other._hashedValue) || _hashedValue.AsSpan().SequenceEqual(other._hashedValue))
               && _issueDate == other._issueDate
               && _expirationDate == other._expirationDate;
    }

    public override byte[] GetHashedValue()
    {
        return _hashedValue;
    }

    public override long GetIssueDate()
    {
        return _issueDate;
    }

    public override long GetExpirationDate()
    {
        return _expirationDate;
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(null, obj))
        {
            return false;
        }

        if (ReferenceEquals(this, obj))
        {
            return true;
        }

        if (obj.GetType() != GetType())
        {
            return false;
        }

        return Equals((InMemoryClientSecret) obj);
    }

    public override int GetHashCode()
    {
        var hashedValueHashCode = 0;
        foreach (var hashedValueByte in _hashedValue)
        {
            hashedValueHashCode = HashCode.Combine(hashedValueHashCode, hashedValueByte.GetHashCode());
        }

        return HashCode.Combine(hashedValueHashCode, _issueDate, _expirationDate);
    }

    public static bool operator ==(InMemoryClientSecret? left, InMemoryClientSecret? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(InMemoryClientSecret? left, InMemoryClientSecret? right)
    {
        return !Equals(left, right);
    }
}
