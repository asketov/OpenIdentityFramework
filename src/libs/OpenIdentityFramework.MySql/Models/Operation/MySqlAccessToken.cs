using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.MySql.Models.Authentication;

namespace OpenIdentityFramework.MySql.Models.Operation;

public class MySqlAccessToken : AbstractAccessToken<MySqlResourceOwnerEssentialClaims, MySqlResourceOwnerIdentifiers>
{
    public MySqlAccessToken(
        string clientId,
        MySqlResourceOwnerEssentialClaims? essentialResourceOwnerClaims,
        IReadOnlySet<string> grantedScopes,
        IReadOnlySet<LightweightClaim> claims,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(clientId));
        }

        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(grantedScopes);

        ClientId = clientId;
        EssentialResourceOwnerClaims = essentialResourceOwnerClaims;
        GrantedScopes = grantedScopes;
        Claims = claims;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    public string ClientId { get; }
    public MySqlResourceOwnerEssentialClaims? EssentialResourceOwnerClaims { get; }
    public IReadOnlySet<string> GrantedScopes { get; }
    public IReadOnlySet<LightweightClaim> Claims { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

    public override string GetClientId()
    {
        return ClientId;
    }

    public override MySqlResourceOwnerEssentialClaims? GetEssentialResourceOwnerClaims()
    {
        return EssentialResourceOwnerClaims;
    }

    public override IReadOnlySet<string> GetGrantedScopes()
    {
        return GrantedScopes;
    }

    public override IReadOnlySet<LightweightClaim> GetClaims()
    {
        return Claims;
    }

    public override DateTimeOffset GetIssueDate()
    {
        return IssuedAt;
    }

    public override DateTimeOffset GetExpirationDate()
    {
        return ExpiresAt;
    }
}
