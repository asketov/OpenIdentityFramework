using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Services.Operation.Models.UserProfileService;

namespace OpenIdentityFramework.Host.Mvc.Services;

public class LocalUserProfileService<TRequestContext, TResourceOwnerIdentifiers> : IUserProfileService<TRequestContext, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public Task GetProfileAsync(TRequestContext requestContext, UserProfileContext<TResourceOwnerIdentifiers> resultContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(resultContext);
        if (requestContext.HttpContext.User.Identity is ClaimsIdentity { IsAuthenticated: true } identity)
        {
            resultContext.Active(identity.Claims.Where(x => resultContext.RequestedClaimTypes.Contains(x.Type)).Select(static x => LightweightClaim.FromClaim(x)));
        }
        else
        {
            resultContext.Disabled();
        }

        return Task.CompletedTask;
    }

    public Task<bool> IsActiveAsync(TRequestContext requestContext, TResourceOwnerIdentifiers resourceOwnerIdentifiers, CancellationToken cancellationToken)
    {
        return Task.FromResult(true);
    }
}
