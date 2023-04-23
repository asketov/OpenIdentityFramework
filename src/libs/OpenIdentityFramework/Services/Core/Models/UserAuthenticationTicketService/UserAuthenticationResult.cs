using System;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

public class UserAuthenticationResult
{
    public UserAuthenticationResult(UserAuthenticationTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        IsAuthenticated = true;
        Ticket = ticket;
        HasError = false;
        ErrorDescription = null;
    }

    public UserAuthenticationResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        IsAuthenticated = false;
        Ticket = null;
        HasError = true;
        ErrorDescription = errorDescription;
    }

    public UserAuthenticationResult()
    {
        IsAuthenticated = false;
        Ticket = null;
        HasError = false;
        ErrorDescription = null;
    }

    [MemberNotNullWhen(true, nameof(Ticket))]
    public bool IsAuthenticated { get; }

    public UserAuthenticationTicket? Ticket { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    public bool HasError { get; }

    public string? ErrorDescription { get; }
}
