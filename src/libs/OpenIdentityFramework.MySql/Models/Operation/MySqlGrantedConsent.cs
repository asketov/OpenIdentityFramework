using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.MySql.Models.Operation;

public class MySqlGrantedConsent : AbstractGrantedConsent
{
    public MySqlGrantedConsent(
        string subjectId,
        string clientId,
        IReadOnlySet<string> grantedScopes,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt)
    {
        if (string.IsNullOrEmpty(subjectId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(subjectId));
        }

        if (string.IsNullOrEmpty(clientId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(clientId));
        }

        ArgumentNullException.ThrowIfNull(grantedScopes);

        SubjectId = subjectId;
        ClientId = clientId;
        GrantedScopes = grantedScopes;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public string SubjectId { get; }
    public string ClientId { get; }
    public IReadOnlySet<string> GrantedScopes { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset? ExpiresAt { get; }

    public override string GetSubjectId()
    {
        return SubjectId;
    }

    public override string GetClientId()
    {
        return ClientId;
    }

    public override IReadOnlySet<string> GetGrantedScopes()
    {
        return GrantedScopes;
    }

    public override DateTimeOffset GetCreationDate()
    {
        return CreatedAt;
    }

    public override DateTimeOffset? GetExpirationDate()
    {
        return ExpiresAt;
    }
}
