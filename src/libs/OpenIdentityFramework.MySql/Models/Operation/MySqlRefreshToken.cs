using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.MySql.Models.Authentication;

namespace OpenIdentityFramework.MySql.Models.Operation;

public class MySqlRefreshToken : AbstractRefreshToken<MySqlResourceOwnerEssentialClaims, MySqlResourceOwnerIdentifiers>
{
    public MySqlRefreshToken(
        string clientId,
        MySqlResourceOwnerEssentialClaims essentialResourceOwnerClaims,
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
    public MySqlResourceOwnerEssentialClaims EssentialResourceOwnerClaims { get; }
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

    public override MySqlResourceOwnerEssentialClaims GetEssentialResourceOwnerClaims()
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
