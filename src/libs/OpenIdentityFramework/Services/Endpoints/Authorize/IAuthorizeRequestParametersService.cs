using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestParametersService<TRequestContext, TAuthorizeRequestParameters>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequestParameters : AbstractAuthorizeRequestParameters
{
    Task<string> SaveAsync(
        TRequestContext requestContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken);

    Task<TAuthorizeRequestParameters?> ReadAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);
}
