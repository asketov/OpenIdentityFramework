using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestParametersService<TAuthorizeRequestParameters>
    where TAuthorizeRequestParameters : AbstractAuthorizeRequestParameters
{
    Task<string> SaveAsync(
        HttpContext httpContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken);

    Task<TAuthorizeRequestParameters?> ReadAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);
}
