using System;
using System.Collections.Generic;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.InMemory.Models.Operation;

public class InMemoryRefreshToken : AbstractRefreshToken<InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>
{
    public InMemoryRefreshToken(
        string clientId,
        InMemoryResourceOwnerEssentialClaims essentialResourceOwnerClaims,
        IReadOnlySet<string> grantedScopes,
        string? referenceAccessTokenHandle,
        string? parentRefreshTokenHandle,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        DateTimeOffset? absoluteExpiresAt)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(clientId));
        }

        ArgumentNullException.ThrowIfNull(essentialResourceOwnerClaims);
        ArgumentNullException.ThrowIfNull(grantedScopes);

        ClientId = clientId;
        EssentialResourceOwnerClaims = essentialResourceOwnerClaims;
        GrantedScopes = grantedScopes;
        ReferenceAccessTokenHandle = referenceAccessTokenHandle;
        ParentRefreshTokenHandle = parentRefreshTokenHandle;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        AbsoluteExpiresAt = absoluteExpiresAt;
    }

    public string ClientId { get; }
    public InMemoryResourceOwnerEssentialClaims EssentialResourceOwnerClaims { get; }
    public IReadOnlySet<string> GrantedScopes { get; }
    public string? ReferenceAccessTokenHandle { get; }
    public string? ParentRefreshTokenHandle { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public DateTimeOffset? AbsoluteExpiresAt { get; }

    public override string GetClientId()
    {
        return ClientId;
    }

    public override InMemoryResourceOwnerEssentialClaims GetEssentialResourceOwnerClaims()
    {
        return EssentialResourceOwnerClaims;
    }

    public override IReadOnlySet<string> GetGrantedScopes()
    {
        return GrantedScopes;
    }

    public override string? GetReferenceAccessTokenHandle()
    {
        return ReferenceAccessTokenHandle;
    }

    public override string? GetParentRefreshTokenHandle()
    {
        return ParentRefreshTokenHandle;
    }

    public override DateTimeOffset GetIssueDate()
    {
        return IssuedAt;
    }

    public override DateTimeOffset GetExpirationDate()
    {
        return ExpiresAt;
    }

    public override DateTimeOffset? GetAbsoluteExpirationDate()
    {
        return AbsoluteExpiresAt;
    }
}
