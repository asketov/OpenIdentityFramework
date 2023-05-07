using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractAuthorizeRequestConsent
{
    public abstract ResourceOwnerIdentifiers GetResourceOwnerIdentifiers();

    public abstract bool HasGranted(
        [NotNullWhen(false)] out ProtocolError? error,
        [NotNullWhen(true)] out (IReadOnlySet<string> AllowedScopes, bool Remember)? consent);

    public abstract DateTimeOffset? GetExpirationDate();
}
