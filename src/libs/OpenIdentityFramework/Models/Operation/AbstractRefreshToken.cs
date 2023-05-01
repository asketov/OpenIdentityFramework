using System.Collections.Generic;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractRefreshToken
{
    public abstract string GetClientId();
    public abstract IReadOnlySet<string> GetGrantedScopes();

    public abstract UserAuthentication GetUserAuthentication();
    public abstract string? GetReferenceAccessTokenHandle();
}
