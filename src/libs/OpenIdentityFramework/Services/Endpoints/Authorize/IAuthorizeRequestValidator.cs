using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestValidator
{
    Task<AuthorizeRequestValidationResult> ValidateAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset requestDate,
        string issuer,
        CancellationToken cancellationToken);
}
