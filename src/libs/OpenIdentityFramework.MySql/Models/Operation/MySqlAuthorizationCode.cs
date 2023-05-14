using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.MySql.Models.Authentication;

namespace OpenIdentityFramework.MySql.Models.Operation;

public class MySqlAuthorizationCode : AbstractAuthorizationCode<MySqlResourceOwnerEssentialClaims, MySqlResourceOwnerIdentifiers>
{
    public MySqlAuthorizationCode(
        string clientId,
        MySqlResourceOwnerEssentialClaims essentialResourceOwnerClaims,
        IReadOnlySet<string> grantedScopes,
        string authorizeRequestRedirectUri,
        string codeChallenge,
        string codeChallengeMethod,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(clientId));
        }

        if (string.IsNullOrEmpty(authorizeRequestRedirectUri))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(authorizeRequestRedirectUri));
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
        AuthorizeRequestRedirectUri = authorizeRequestRedirectUri;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = codeChallengeMethod;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    public string ClientId { get; }
    public MySqlResourceOwnerEssentialClaims EssentialResourceOwnerClaims { get; }
    public IReadOnlySet<string> GrantedScopes { get; }
    public string? AuthorizeRequestRedirectUri { get; }
    public string CodeChallenge { get; }
    public string CodeChallengeMethod { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

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

    public override string? GetAuthorizeRequestRedirectUri()
    {
        return AuthorizeRequestRedirectUri;
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
