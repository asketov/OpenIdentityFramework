using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Core;

public interface IUserAuthenticationTicketService<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<UserAuthenticationResult> AuthenticateAsync(TRequestContext requestContext, CancellationToken cancellationToken);
}
