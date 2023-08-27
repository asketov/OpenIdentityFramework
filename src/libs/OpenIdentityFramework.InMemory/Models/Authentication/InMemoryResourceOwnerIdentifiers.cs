using System;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.InMemory.Models.Authentication;

public class InMemoryResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public InMemoryResourceOwnerIdentifiers(string subjectId, string sessionId)
    {
        if (string.IsNullOrEmpty(subjectId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(subjectId));
        }

        if (string.IsNullOrEmpty(sessionId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(sessionId));
        }

        SubjectId = subjectId;
        SessionId = sessionId;
    }

    protected string SubjectId { get; }
    protected string SessionId { get; }

    public override string GetSubjectId()
    {
        return SubjectId;
    }

    public override string GetSessionId()
    {
        return SessionId;
    }
}
