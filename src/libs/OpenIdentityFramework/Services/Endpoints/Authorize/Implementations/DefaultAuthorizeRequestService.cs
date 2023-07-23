using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeRequestService<TRequestContext, TAuthorizeRequest>
    : IAuthorizeRequestService<TRequestContext, TAuthorizeRequest>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequest : AbstractAuthorizeRequest
{
    public DefaultAuthorizeRequestService(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthorizeRequestStorage<TRequestContext, TAuthorizeRequest> storage,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(timeProvider);
        FrameworkOptions = frameworkOptions;
        Storage = storage;
        TimeProvider = timeProvider;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IAuthorizeRequestStorage<TRequestContext, TAuthorizeRequest> Storage { get; }
    protected TimeProvider TimeProvider { get; }

    public virtual async Task<string> SaveAsync(
        TRequestContext requestContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var expiresAt = initialRequestDate.Add(FrameworkOptions.Endpoints.Authorize.AuthorizeRequestLifetime);
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(TimeProvider.GetUtcNow().ToUnixTimeSeconds());
        return await Storage.SaveAsync(requestContext, initialRequestDate, parameters, createdAt, expiresAt, cancellationToken);
    }

    public virtual async Task<TAuthorizeRequest?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var parameters = await Storage.FindAsync(requestContext, authorizeRequestId, cancellationToken);
        if (parameters != null)
        {
            var currentDate = TimeProvider.GetUtcNow();
            var expirationDate = parameters.GetExpirationDate();
            if (currentDate > expirationDate)
            {
                await DeleteAsync(requestContext, authorizeRequestId, cancellationToken);
                return null;
            }

            return parameters;
        }

        return null;
    }

    public virtual async Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DeleteAsync(requestContext, authorizeRequestId, cancellationToken);
    }
}
