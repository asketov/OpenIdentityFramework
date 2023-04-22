using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractAuthorizeRequestConsent
{
    public abstract bool HasGranted(
        [NotNullWhen(false)] out ProtocolError? error,
        [NotNullWhen(true)] out (IReadOnlySet<string> AllowedScopes, bool Remember)? consent);
}
