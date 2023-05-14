using System;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.MySql.Models.Authentication;

public class MySqlResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public MySqlResourceOwnerIdentifiers(string subjectId, string sessionId)
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

    public string SubjectId { get; }

    public string SessionId { get; }

    public override string GetSubjectId()
    {
        return SubjectId;
    }

    public override string GetSessionId()
    {
        return SessionId;
    }
}
