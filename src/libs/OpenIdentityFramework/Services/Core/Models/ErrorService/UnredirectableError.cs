using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Core.Models.ErrorService;

public class UnredirectableError
{
    public UnredirectableError(ProtocolError protocolError, string? clientId, string? redirectUri, string? responseMode, string issuer)
    {
        ProtocolError = protocolError;
        ClientId = clientId;
        RedirectUri = redirectUri;
        ResponseMode = responseMode;
        Issuer = issuer;
    }

    public ProtocolError ProtocolError { get; }
    public string? ClientId { get; }
    public string? RedirectUri { get; }
    public string? ResponseMode { get; }
    public string Issuer { get; }
}
