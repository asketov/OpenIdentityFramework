using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Services.Operation.Models.UserProfileService;

namespace OpenIdentityFramework.Services.Operation;

public interface IUserProfileService<TRequestContext, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task GetProfileAsync(
        TRequestContext requestContext,
        UserProfileContext<TResourceOwnerIdentifiers> resultContext,
        CancellationToken cancellationToken);

    Task<bool> IsActiveAsync(
        TRequestContext requestContext,
        TResourceOwnerIdentifiers resourceOwnerIdentifiers,
        CancellationToken cancellationToken);
}
