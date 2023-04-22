using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationService;

namespace OpenIdentityFramework.Services.Core;

public interface IUserAuthenticationService
{
    Task<UserAuthenticationResult> AuthenticateAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
