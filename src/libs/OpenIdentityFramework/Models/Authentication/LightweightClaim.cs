using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace OpenIdentityFramework.Models.Authentication;

public class LightweightClaim : IEquatable<LightweightClaim>
{
    public LightweightClaim(string type, string value, string valueType = ClaimValueTypes.String)
    {
        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(type));
        }

        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(value));
        }

        if (string.IsNullOrEmpty(valueType))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(valueType));
        }

        Type = type;
        Value = value;
        ValueType = valueType;
    }

    public static IEqualityComparer<LightweightClaim> EqualityComparer { get; } = new LightweightClaimEqualityComparer();

    public string Type { get; }

    public string Value { get; }

    public string ValueType { get; }

    public bool Equals(LightweightClaim? other)
    {
        if (ReferenceEquals(null, other))
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return Type == other.Type && Value == other.Value && ValueType == other.ValueType;
    }

    public static LightweightClaim FromClaim(Claim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        return new(claim.Type, claim.Value, claim.ValueType);
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

        return Equals((LightweightClaim) obj);
    }

    public override int GetHashCode()
    {
        unchecked
        {
            var hashCode = Type.GetHashCode(StringComparison.Ordinal);
            hashCode = (hashCode * 397) ^ Value.GetHashCode(StringComparison.Ordinal);
            hashCode = (hashCode * 397) ^ ValueType.GetHashCode(StringComparison.Ordinal);
            return hashCode;
        }
    }

    public static bool operator ==(LightweightClaim? left, LightweightClaim? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(LightweightClaim? left, LightweightClaim? right)
    {
        return !Equals(left, right);
    }

    private sealed class LightweightClaimEqualityComparer : IEqualityComparer<LightweightClaim>
    {
        public bool Equals(LightweightClaim? x, LightweightClaim? y)
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

            return x.Type == y.Type && x.Value == y.Value && x.ValueType == y.ValueType;
        }

        public int GetHashCode(LightweightClaim obj)
        {
            unchecked
            {
                var hashCode = obj.Type.GetHashCode(StringComparison.Ordinal);
                hashCode = (hashCode * 397) ^ obj.Value.GetHashCode(StringComparison.Ordinal);
                hashCode = (hashCode * 397) ^ obj.ValueType.GetHashCode(StringComparison.Ordinal);
                return hashCode;
            }
        }
    }
}
