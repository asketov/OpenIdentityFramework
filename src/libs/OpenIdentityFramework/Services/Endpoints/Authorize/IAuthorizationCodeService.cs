using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        CreateAuthorizationCodeRequest<TClient, TClientSecret> createRequest,
        CancellationToken cancellationToken);

    Task<TAuthorizationCode?> FindAsync(
        TRequestContext requestContext,
        string authorizationCode,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizationCode,
        CancellationToken cancellationToken);
}
