using System;
using Microsoft.AspNetCore.Authentication;

namespace OpenIdentityFramework.Services.Core.Models.UserAuthenticationService;

public class UserAuthentication
{
    public UserAuthentication(string subjectId, string sessionId, DateTimeOffset authenticatedAt, AuthenticationTicket ticket)
    {
        SubjectId = subjectId;
        SessionId = sessionId;
        AuthenticatedAt = authenticatedAt;
        Ticket = ticket;
    }

    public string SubjectId { get; }

    public string SessionId { get; }

    public DateTimeOffset AuthenticatedAt { get; }

    public AuthenticationTicket Ticket { get; }
}
