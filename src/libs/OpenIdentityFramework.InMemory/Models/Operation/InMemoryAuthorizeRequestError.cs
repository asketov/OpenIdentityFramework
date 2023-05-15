using System;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.InMemory.Models.Operation;

public class InMemoryAuthorizeRequestError : AbstractAuthorizeRequestError
{
    public InMemoryAuthorizeRequestError(
        ProtocolError protocolError,
        string? clientId,
        string? redirectUri,
        string? responseMode,
        string? state,
        string issuer,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        if (string.IsNullOrEmpty(issuer))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(issuer));
        }

        ArgumentNullException.ThrowIfNull(protocolError);
        ProtocolError = protocolError;
        ClientId = clientId;
        RedirectUri = redirectUri;
        ResponseMode = responseMode;
        State = state;
        Issuer = issuer;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public ProtocolError ProtocolError { get; }
    public string? ClientId { get; }
    public string? RedirectUri { get; }
    public string? ResponseMode { get; }
    public string? State { get; }
    public string Issuer { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }


    public override ProtocolError GetProtocolError()
    {
        return ProtocolError;
    }

    public override string? GetClientId()
    {
        return ClientId;
    }

    public override string? GetRedirectUri()
    {
        return RedirectUri;
    }

    public override string? GetResponseMode()
    {
        return ResponseMode;
    }

    public override string? GetState()
    {
        return State;
    }

    public override string GetIssuer()
    {
        return Issuer;
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
