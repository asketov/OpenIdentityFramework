using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Operation;

public interface IUserProfileService
{
    Task<bool> IsActiveAsync(
        HttpContext httpContext,
        UserAuthentication ticket,
        CancellationToken cancellationToken);

    Task<IReadOnlySet<LightweightClaim>> GetProfileClaimsAsync(
        HttpContext httpContext,
        UserAuthentication ticket,
        IReadOnlySet<string> requestedClaimTypes,
        CancellationToken cancellationToken);
}
