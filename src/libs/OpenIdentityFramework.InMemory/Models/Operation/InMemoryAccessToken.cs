using System;
using System.Collections.Generic;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.InMemory.Models.Operation;

public class InMemoryAccessToken : AbstractAccessToken<InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>
{
    public InMemoryAccessToken(
        string clientId,
        InMemoryResourceOwnerEssentialClaims? essentialResourceOwnerClaims,
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
    public InMemoryResourceOwnerEssentialClaims? EssentialResourceOwnerClaims { get; }
    public IReadOnlySet<string> GrantedScopes { get; }
    public IReadOnlySet<LightweightClaim> Claims { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

    public override string GetClientId()
    {
        return ClientId;
    }

    public override InMemoryResourceOwnerEssentialClaims? GetEssentialResourceOwnerClaims()
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
