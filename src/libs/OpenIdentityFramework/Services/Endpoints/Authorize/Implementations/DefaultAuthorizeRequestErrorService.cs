using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError>
    : IAuthorizeRequestErrorService<TRequestContext, TAuthorizeRequestError>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequestError : AbstractAuthorizeRequestError
{
    public DefaultAuthorizeRequestErrorService(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthorizeRequestErrorStorage<TRequestContext, TAuthorizeRequestError> storage,
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
    protected IAuthorizeRequestErrorStorage<TRequestContext, TAuthorizeRequestError> Storage { get; }
    protected TimeProvider TimeProvider { get; }

    public virtual async Task<string> CreateAsync(
        TRequestContext requestContext,
        ProtocolError protocolError,
        string? clientId,
        string? redirectUri,
        string? responseMode,
        string? state,
        string issuer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(TimeProvider.GetUtcNow().ToUnixTimeSeconds());
        var expiresAt = createdAt.Add(FrameworkOptions.Endpoints.Authorize.AuthorizeRequestErrorsLifetime);
        return await Storage.CreateAsync(
            requestContext,
            protocolError,
            clientId,
            redirectUri,
            responseMode,
            state,
            issuer,
            createdAt,
            expiresAt,
            cancellationToken);
    }

    public virtual async Task<TAuthorizeRequestError?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestErrorHandle,
        CancellationToken cancellationToken)
    {
        return await Storage.FindAsync(requestContext, authorizeRequestErrorHandle, cancellationToken);
    }

    public virtual async Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestErrorHandle,
        CancellationToken cancellationToken)
    {
        await Storage.DeleteAsync(requestContext, authorizeRequestErrorHandle, cancellationToken);
    }
}
