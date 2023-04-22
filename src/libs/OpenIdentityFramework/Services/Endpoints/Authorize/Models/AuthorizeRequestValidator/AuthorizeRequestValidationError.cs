using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

public class AuthorizeRequestValidationError<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public AuthorizeRequestValidationError(
        DateTimeOffset requestDate,
        string issuer,
        ProtocolError protocolError)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(issuer));
        }

        ArgumentNullException.ThrowIfNull(protocolError);
        RequestDate = requestDate;
        Issuer = issuer;
        ProtocolError = protocolError;
    }

    public AuthorizeRequestValidationError(
        DateTimeOffset requestDate,
        string issuer,
        ProtocolError protocolError,
        TClient client,
        string redirectUri,
        string responseMode,
        string? state)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(issuer));
        }

        ArgumentNullException.ThrowIfNull(protocolError);
        ArgumentNullException.ThrowIfNull(client);

        if (string.IsNullOrWhiteSpace(redirectUri))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(redirectUri));
        }

        if (string.IsNullOrWhiteSpace(responseMode))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseMode));
        }

        RequestDate = requestDate;
        Issuer = issuer;
        ProtocolError = protocolError;
        Client = client;
        RedirectUri = redirectUri;
        State = state;
        ResponseMode = responseMode;
        CanReturnErrorDirectly = true;
    }

    public DateTimeOffset RequestDate { get; }
    public string Issuer { get; }
    public ProtocolError ProtocolError { get; }
    public TClient? Client { get; }
    public string? RedirectUri { get; }
    public string? ResponseMode { get; }
    public string? State { get; }

    [MemberNotNullWhen(true, nameof(Client))]
    [MemberNotNullWhen(true, nameof(RedirectUri))]
    [MemberNotNullWhen(true, nameof(ResponseMode))]
    public bool CanReturnErrorDirectly { get; }
}
