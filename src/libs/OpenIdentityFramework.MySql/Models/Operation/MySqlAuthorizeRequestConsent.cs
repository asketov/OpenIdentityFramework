using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;
using OpenIdentityFramework.MySql.Models.Authentication;

namespace OpenIdentityFramework.MySql.Models.Operation;

public class MySqlAuthorizeRequestConsent : AbstractAuthorizeRequestConsent<MySqlResourceOwnerIdentifiers>
{
    public MySqlAuthorizeRequestConsent(
        MySqlResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentGranted grantedConsent,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(authorIdentifiers);
        ArgumentNullException.ThrowIfNull(grantedConsent);

        AuthorIdentifiers = authorIdentifiers;
        HasGrantedConsent = true;
        GrantedConsent = grantedConsent;
        DeniedConsent = null;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public MySqlAuthorizeRequestConsent(
        MySqlResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentDenied deniedConsent,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(authorIdentifiers);
        ArgumentNullException.ThrowIfNull(deniedConsent);

        AuthorIdentifiers = authorIdentifiers;
        HasGrantedConsent = false;
        GrantedConsent = null;
        DeniedConsent = deniedConsent;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public MySqlResourceOwnerIdentifiers AuthorIdentifiers { get; }

    [MemberNotNullWhen(true, nameof(GrantedConsent))]
    [MemberNotNullWhen(false, nameof(DeniedConsent))]
    public bool HasGrantedConsent { get; }

    public AuthorizeRequestConsentGranted? GrantedConsent { get; }

    public AuthorizeRequestConsentDenied? DeniedConsent { get; }

    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

    public override MySqlResourceOwnerIdentifiers GetAuthorIdentifiers()
    {
        return AuthorIdentifiers;
    }

    public override bool TryGetGrantedConsent(
        [NotNullWhen(true)] out AuthorizeRequestConsentGranted? grantedConsent,
        [NotNullWhen(false)] out AuthorizeRequestConsentDenied? deniedConsent)
    {
        if (HasGrantedConsent)
        {
            grantedConsent = GrantedConsent;
            deniedConsent = null;
            return true;
        }

        grantedConsent = null;
        deniedConsent = DeniedConsent;
        return false;
    }

    public override DateTimeOffset GetCreationDate()
    {
        return CreatedAt;
    }

    public override DateTimeOffset GetExpirationDate()
    {
        return ExpiresAt;
    }
}
