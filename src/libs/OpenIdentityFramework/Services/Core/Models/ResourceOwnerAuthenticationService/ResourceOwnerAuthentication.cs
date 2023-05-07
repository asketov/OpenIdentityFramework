using System;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;

public class ResourceOwnerAuthentication
{
    public ResourceOwnerAuthentication(EssentialResourceOwnerClaims essentialClaims, AuthenticationTicket authenticationTicket)
    {
        ArgumentNullException.ThrowIfNull(essentialClaims);
        ArgumentNullException.ThrowIfNull(authenticationTicket);
        EssentialClaims = essentialClaims;
        AuthenticationTicket = authenticationTicket;
    }

    public EssentialResourceOwnerClaims EssentialClaims { get; }
    public AuthenticationTicket AuthenticationTicket { get; }
}
