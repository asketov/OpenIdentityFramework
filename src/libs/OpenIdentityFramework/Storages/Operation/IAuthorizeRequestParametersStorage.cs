using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizeRequestParametersStorage<TAuthorizeRequestParameters>
    where TAuthorizeRequestParameters : AbstractAuthorizeRequestParameters
{
    Task<string> SaveAsync(
        HttpContext httpContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken);

    Task<TAuthorizeRequestParameters?> FindAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);
}
