using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizeRequestErrorStorage<TRequestContext, TAuthorizeRequestError>
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
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
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
