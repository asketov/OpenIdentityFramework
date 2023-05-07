using System;

namespace OpenIdentityFramework.Models.Authentication;

public class ResourceOwnerIdentifiers : IEquatable<ResourceOwnerIdentifiers>
{
    public ResourceOwnerIdentifiers(string subjectId, string sessionId)
    {
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(subjectId));
        }

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(sessionId));
        }

        SubjectId = subjectId;
        SessionId = sessionId;
    }

    public string SubjectId { get; }

    public string SessionId { get; }

    public bool Equals(ResourceOwnerIdentifiers? other)
    {
        if (ReferenceEquals(null, other))
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return SubjectId == other.SubjectId && SessionId == other.SessionId;
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

        return Equals((ResourceOwnerIdentifiers) obj);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(SubjectId, SessionId);
    }

    public static bool operator ==(ResourceOwnerIdentifiers? left, ResourceOwnerIdentifiers? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(ResourceOwnerIdentifiers? left, ResourceOwnerIdentifiers? right)
    {
        return !Equals(left, right);
    }
}
