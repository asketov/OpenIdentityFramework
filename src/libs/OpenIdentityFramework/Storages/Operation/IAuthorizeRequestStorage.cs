using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizeRequestStorage<TRequestContext, TAuthorizeRequest>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequest : AbstractAuthorizeRequest
{
    Task<string> SaveAsync(
        TRequestContext requestContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    Task<TAuthorizeRequest?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestHandle,
        CancellationToken cancellationToken);


    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestHandle,
        CancellationToken cancellationToken);
}
