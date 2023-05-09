using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Services.Operation.Models;

namespace OpenIdentityFramework.Services.Operation;

public interface IUserProfileService<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    Task GetProfileAsync(
        TRequestContext requestContext,
        UserProfileContext context,
        CancellationToken cancellationToken);

    Task<bool> IsActiveAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        CancellationToken cancellationToken);
}
