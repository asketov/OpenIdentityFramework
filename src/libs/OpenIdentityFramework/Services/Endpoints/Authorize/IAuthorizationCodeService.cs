using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizationCodeService<TClient, TClientSecret, TAuthorizationCode>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    Task<string> CreateAsync(
        HttpContext httpContext,
        AuthorizationCodeRequest<TClient, TClientSecret> codeRequest,
        CancellationToken cancellationToken);

    Task<TAuthorizationCode?> FindAsync(
        HttpContext httpContext,
        string authorizationCode,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        HttpContext httpContext,
        string authorizationCode,
        CancellationToken cancellationToken);
}
