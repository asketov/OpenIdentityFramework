using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Core;

public interface IResourceOwnerServerSessionService<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    Task<string> StoreAsync(TRequestContext requestContext, AuthenticationTicket ticket, CancellationToken cancellationToken);

    Task RenewAsync(TRequestContext requestContext, string key, AuthenticationTicket ticket, CancellationToken cancellationToken);

    Task<AuthenticationTicket?> RetrieveAsync(TRequestContext requestContext, string key, CancellationToken cancellationToken);

    Task RemoveAsync(TRequestContext requestContext, string key, CancellationToken cancellationToken);
}
