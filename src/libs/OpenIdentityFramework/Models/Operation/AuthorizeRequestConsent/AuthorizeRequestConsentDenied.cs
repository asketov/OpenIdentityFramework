using System;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;

public class AuthorizeRequestConsentDenied
{
    public AuthorizeRequestConsentDenied(ResourceOwnerIdentifiers author, ProtocolError? error)
    {
        ArgumentNullException.ThrowIfNull(author);
        Error = error;
    }

    public ProtocolError? Error { get; }
}
