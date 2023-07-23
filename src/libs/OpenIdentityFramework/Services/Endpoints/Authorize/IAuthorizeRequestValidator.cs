using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
{
    Task<AuthorizeRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> ValidateAsync(
        TRequestContext requestContext,
        IReadOnlyDictionary<string, StringValues> rawParameters,
        DateTimeOffset initialRequestDate,
        string issuer,
        CancellationToken cancellationToken);
}
