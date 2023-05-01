using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

public class UserAuthentication
{
    public UserAuthentication(string subjectId, string sessionId, DateTimeOffset authenticatedAt, IReadOnlySet<LightweightClaim> customClaims)
    {
        SubjectId = subjectId;
        SessionId = sessionId;
        AuthenticatedAt = authenticatedAt;
        CustomClaims = customClaims;
    }

    public string SubjectId { get; }

    public string SessionId { get; }

    public DateTimeOffset AuthenticatedAt { get; }

    public IReadOnlySet<LightweightClaim> CustomClaims { get; }
}
