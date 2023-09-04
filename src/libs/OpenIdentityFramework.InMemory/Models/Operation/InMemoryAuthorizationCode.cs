using System;
using System.Collections.Generic;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.InMemory.Models.Operation;

public class InMemoryAuthorizationCode : AbstractAuthorizationCode<InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>
{
    public InMemoryAuthorizationCode(
        string clientId,
        InMemoryResourceOwnerEssentialClaims essentialResourceOwnerClaims,
        IReadOnlySet<string> grantedScopes,
        string codeChallenge,
        string codeChallengeMethod,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(clientId));
        }

        if (string.IsNullOrEmpty(codeChallenge))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(codeChallenge));
        }

        if (string.IsNullOrEmpty(codeChallengeMethod))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(codeChallengeMethod));
        }

        ArgumentNullException.ThrowIfNull(grantedScopes);
        ArgumentNullException.ThrowIfNull(essentialResourceOwnerClaims);

        ClientId = clientId;
        EssentialResourceOwnerClaims = essentialResourceOwnerClaims;
        GrantedScopes = grantedScopes;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = codeChallengeMethod;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    public string ClientId { get; }
    public InMemoryResourceOwnerEssentialClaims EssentialResourceOwnerClaims { get; }
    public IReadOnlySet<string> GrantedScopes { get; }
    public string CodeChallenge { get; }
    public string CodeChallengeMethod { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

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

    public override string GetCodeChallenge()
    {
        return CodeChallenge;
    }

    public override string GetCodeChallengeMethod()
    {
        return CodeChallengeMethod;
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
