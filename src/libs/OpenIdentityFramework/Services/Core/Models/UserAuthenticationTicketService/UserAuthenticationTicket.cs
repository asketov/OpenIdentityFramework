using System;
using Microsoft.AspNetCore.Authentication;

namespace OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

public class UserAuthenticationTicket
{
    public UserAuthenticationTicket(UserAuthentication userAuthentication, AuthenticationTicket authenticationTicket)
    {
        ArgumentNullException.ThrowIfNull(userAuthentication);
        ArgumentNullException.ThrowIfNull(authenticationTicket);
        UserAuthentication = userAuthentication;
        AuthenticationTicket = authenticationTicket;
    }

    public UserAuthentication UserAuthentication { get; }

    public AuthenticationTicket AuthenticationTicket { get; }
}
