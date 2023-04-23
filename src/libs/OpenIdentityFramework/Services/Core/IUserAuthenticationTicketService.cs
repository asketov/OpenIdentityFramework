using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Core;

public interface IUserAuthenticationTicketService
{
    Task<UserAuthenticationResult> AuthenticateAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
