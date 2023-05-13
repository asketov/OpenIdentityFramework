using System;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;

public class ResourceOwnerAuthentication<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public ResourceOwnerAuthentication(TResourceOwnerEssentialClaims essentialClaims, AuthenticationTicket authenticationTicket)
    {
        ArgumentNullException.ThrowIfNull(essentialClaims);
        ArgumentNullException.ThrowIfNull(authenticationTicket);
        EssentialClaims = essentialClaims;
        AuthenticationTicket = authenticationTicket;
    }

    public TResourceOwnerEssentialClaims EssentialClaims { get; }
    public AuthenticationTicket AuthenticationTicket { get; }
}
