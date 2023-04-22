using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizeRequestParametersStorage
{
    Task<string> SaveAsync(
        HttpContext httpContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken);
}
