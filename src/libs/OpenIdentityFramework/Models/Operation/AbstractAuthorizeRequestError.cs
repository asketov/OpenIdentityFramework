using System;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractAuthorizeRequestError
{
    public abstract ProtocolError GetProtocolError();
    public abstract string? GetClientId();
    public abstract string? GetRedirectUri();
    public abstract string? GetResponseMode();
    public abstract string? GetState();
    public abstract string GetIssuer();
    public abstract DateTimeOffset GetCreationDate();
    public abstract DateTimeOffset GetExpirationDate();
}
