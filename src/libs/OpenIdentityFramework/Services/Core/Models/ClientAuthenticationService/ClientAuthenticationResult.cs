using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.ClientAuthenticationService;

public class ClientAuthenticationResult<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    public ClientAuthenticationResult(TClient client, string clientAuthenticationMethod)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(clientAuthenticationMethod);
        IsAuthenticated = true;
        Client = client;
        ClientAuthenticationMethod = clientAuthenticationMethod;
        HasError = false;
        ErrorDescription = null;
    }

    public ClientAuthenticationResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        IsAuthenticated = false;
        Client = null;
        HasError = true;
        ErrorDescription = errorDescription;
    }

    public ClientAuthenticationResult()
    {
        IsAuthenticated = false;
        Client = null;
        HasError = false;
        ErrorDescription = null;
    }

    [MemberNotNullWhen(true, nameof(Client))]
    [MemberNotNullWhen(true, nameof(ClientAuthenticationMethod))]
    public bool IsAuthenticated { get; }

    public TClient? Client { get; }

    public string? ClientAuthenticationMethod { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    public bool HasError { get; }

    public string? ErrorDescription { get; }
}
