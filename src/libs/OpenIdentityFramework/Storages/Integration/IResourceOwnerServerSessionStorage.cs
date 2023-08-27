using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Storages.Integration;

public interface IResourceOwnerServerSessionStorage<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<string> StoreAsync(
        TRequestContext requestContext,
        AuthenticationTicket ticket,
        TResourceOwnerEssentialClaims resourceOwnerEssentialClaims,
        CancellationToken cancellationToken);

    Task RenewAsync(
        TRequestContext requestContext,
        string key,
        AuthenticationTicket ticket,
        TResourceOwnerEssentialClaims resourceOwnerEssentialClaims,
        CancellationToken cancellationToken);

    Task<AuthenticationTicket?> RetrieveAsync(
        TRequestContext requestContext,
        string key,
        CancellationToken cancellationToken);

    Task RemoveAsync(
        TRequestContext requestContext,
        string key,
        CancellationToken cancellationToken);
}
