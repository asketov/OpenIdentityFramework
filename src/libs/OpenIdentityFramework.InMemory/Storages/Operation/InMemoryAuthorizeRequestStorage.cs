using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.InMemory.Storages.Operation;

public class InMemoryAuthorizeRequestStorage : IAuthorizeRequestStorage<InMemoryRequestContext, InMemoryAuthorizeRequest>
{
    private readonly object _locker;
    private readonly Dictionary<string, InMemoryAuthorizeRequest> _store;

    public InMemoryAuthorizeRequestStorage()
    {
        _store = new(StringComparer.Ordinal);
        _locker = new();
    }

    public Task<string> SaveAsync(
        InMemoryRequestContext requestContext,
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var authorizeRequest = new InMemoryAuthorizeRequest(
            initialRequestDate,
            parameters,
            createdAt,
            expiresAt);
        var authorizeRequestHandle = Guid.NewGuid().ToString("N");
        lock (_locker)
        {
            while (_store.ContainsKey(authorizeRequestHandle))
            {
                authorizeRequestHandle = Guid.NewGuid().ToString("N");
            }

            _store[authorizeRequestHandle] = authorizeRequest;
        }

        return Task.FromResult(authorizeRequestHandle);
    }

    public Task<InMemoryAuthorizeRequest?> FindAsync(
        InMemoryRequestContext requestContext,
        string authorizeRequestHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryAuthorizeRequest? foundAuthorizeRequest = null;
        lock (_locker)
        {
            if (_store.TryGetValue(authorizeRequestHandle, out var authorizeRequest))
            {
                foundAuthorizeRequest = authorizeRequest;
            }
        }

        return Task.FromResult(foundAuthorizeRequest);
    }

    public Task DeleteAsync(
        InMemoryRequestContext requestContext,
        string authorizeRequestHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_locker)
        {
            _store.Remove(authorizeRequestHandle);
        }

        return Task.CompletedTask;
    }
}
