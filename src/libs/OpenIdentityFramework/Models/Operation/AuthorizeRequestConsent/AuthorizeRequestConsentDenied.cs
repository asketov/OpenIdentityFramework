namespace OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;

public class AuthorizeRequestConsentDenied
{
    public AuthorizeRequestConsentDenied(ProtocolError? error)
    {
        Error = error;
    }

    public ProtocolError? Error { get; }
}
