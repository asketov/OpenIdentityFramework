using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractAuthorizeRequestConsent<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public abstract TResourceOwnerIdentifiers GetAuthorIdentifiers();

    public abstract bool TryGetGrantedConsent(
        [NotNullWhen(true)] out AuthorizeRequestConsentGranted? grantedConsent,
        [NotNullWhen(false)] out AuthorizeRequestConsentDenied? deniedConsent);

    public abstract DateTimeOffset GetCreationDate();
    public abstract DateTimeOffset GetExpirationDate();
}
