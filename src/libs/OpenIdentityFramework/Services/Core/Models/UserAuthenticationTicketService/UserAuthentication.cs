using System;

namespace OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

public class UserAuthentication
{
    public UserAuthentication(string subjectId, string sessionId, DateTimeOffset authenticatedAt)
    {
        SubjectId = subjectId;
        SessionId = sessionId;
        AuthenticatedAt = authenticatedAt;
    }

    public string SubjectId { get; }

    public string SessionId { get; }

    public DateTimeOffset AuthenticatedAt { get; }
}
