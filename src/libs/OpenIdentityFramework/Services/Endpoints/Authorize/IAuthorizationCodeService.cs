using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizationCodeService<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    Task<string> CreateAsync(
        HttpContext httpContext,
        AuthorizationCodeRequest<TClient, TClientSecret> codeRequest,
        CancellationToken cancellationToken);
}
