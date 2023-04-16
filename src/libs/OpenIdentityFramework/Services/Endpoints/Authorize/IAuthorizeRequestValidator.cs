using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<AuthorizeRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> ValidateAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset requestDate,
        string issuer,
        CancellationToken cancellationToken);
}
