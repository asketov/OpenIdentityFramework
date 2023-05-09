using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizeRequestParametersStorage<TRequestContext, TAuthorizeRequestParameters>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequestParameters : AbstractAuthorizeRequestParameters
{
    Task<string> SaveAsync(
        TRequestContext requestContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken);

    Task<TAuthorizeRequestParameters?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);
}
