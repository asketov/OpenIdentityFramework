using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationService;

namespace OpenIdentityFramework.Services.Operation;

public interface IUserProfileService
{
    Task<bool> IsActiveAsync(HttpContext httpContext, UserAuthentication userAuthentication, CancellationToken cancellationToken);
}
