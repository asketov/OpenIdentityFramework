using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequestError : AbstractAuthorizeRequestError
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        ProtocolError protocolError,
        string? clientId,
        string? redirectUri,
        string? responseMode,
        string? state,
        string issuer,
        CancellationToken cancellationToken);

    Task<TAuthorizeRequestError?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestErrorHandle,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestErrorHandle,
        CancellationToken cancellationToken);
}
