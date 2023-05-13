using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;

namespace OpenIdentityFramework.Services.Core;

public interface IResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<ResourceOwnerAuthenticationResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> AuthenticateAsync(
        TRequestContext requestContext,
        CancellationToken cancellationToken);
}
