using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeRequestParametersService<TAuthorizeRequestParameters>
    : IAuthorizeRequestParametersService<TAuthorizeRequestParameters>
    where TAuthorizeRequestParameters : AbstractAuthorizeRequestParameters
{
    public DefaultAuthorizeRequestParametersService(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthorizeRequestParametersStorage<TAuthorizeRequestParameters> storage,
        ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        FrameworkOptions = frameworkOptions;
        Storage = storage;
        SystemClock = systemClock;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IAuthorizeRequestParametersStorage<TAuthorizeRequestParameters> Storage { get; }
    protected ISystemClock SystemClock { get; }

    public virtual async Task<string> SaveAsync(
        HttpContext httpContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DateTimeOffset? expiresAt = null;
        if (FrameworkOptions.Endpoints.Authorize.AuthorizeRequestLifetime.HasValue)
        {
            expiresAt = initialRequestDate.Add(FrameworkOptions.Endpoints.Authorize.AuthorizeRequestLifetime.Value);
        }

        return await Storage.SaveAsync(httpContext, initialRequestDate, parameters, expiresAt, cancellationToken);
    }

    public virtual async Task<TAuthorizeRequestParameters?> ReadAsync(HttpContext httpContext, string authorizeRequestId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var parameters = await Storage.FindAsync(httpContext, authorizeRequestId, cancellationToken);
        if (parameters != null)
        {
            var currentDate = SystemClock.UtcNow;
            var expirationDate = parameters.GetExpirationDate();
            if (currentDate > expirationDate)
            {
                await DeleteAsync(httpContext, authorizeRequestId, cancellationToken);
                return null;
            }

            return parameters;
        }

        return null;
    }

    public virtual async Task DeleteAsync(HttpContext httpContext, string authorizeRequestId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DeleteAsync(httpContext, authorizeRequestId, cancellationToken);
    }
}
