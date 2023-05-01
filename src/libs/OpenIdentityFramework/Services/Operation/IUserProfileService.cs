using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Operation;

public interface IUserProfileService<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<bool> IsActiveAsync(
        TRequestContext requestContext,
        UserAuthentication ticket,
        CancellationToken cancellationToken);

    Task<IReadOnlySet<LightweightClaim>> GetProfileClaimsAsync(
        TRequestContext requestContext,
        UserAuthentication ticket,
        IReadOnlySet<string> requestedClaimTypes,
        CancellationToken cancellationToken);
}
