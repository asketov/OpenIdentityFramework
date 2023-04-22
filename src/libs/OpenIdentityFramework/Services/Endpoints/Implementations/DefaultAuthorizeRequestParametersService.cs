using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Implementations;

public class DefaultAuthorizeRequestParametersService : IAuthorizeRequestParametersService
{
    public DefaultAuthorizeRequestParametersService(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthorizeRequestParametersStorage storage)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(storage);
        FrameworkOptions = frameworkOptions;
        Storage = storage;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IAuthorizeRequestParametersStorage Storage { get; }

    public async Task<string> SaveAsync(
        HttpContext httpContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DateTimeOffset? expiresAt = null;
        if (FrameworkOptions.UserInteraction.AuthorizeRequestLifetime.HasValue)
        {
            expiresAt = initialRequestDate.Add(FrameworkOptions.UserInteraction.AuthorizeRequestLifetime.Value);
        }

        return await Storage.SaveAsync(httpContext, initialRequestDate, parameters, expiresAt, cancellationToken);
    }
}
