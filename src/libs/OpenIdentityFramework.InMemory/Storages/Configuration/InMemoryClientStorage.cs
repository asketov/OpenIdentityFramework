using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Configuration;
using OpenIdentityFramework.Storages.Configuration;

namespace OpenIdentityFramework.InMemory.Storages.Configuration;

public class InMemoryClientStorage : IClientStorage<InMemoryRequestContext, InMemoryClient, InMemoryClientSecret>
{
    private readonly FrozenDictionary<string, InMemoryClient> _clients;

    public InMemoryClientStorage(IEnumerable<InMemoryClient> clients)
    {
        ArgumentNullException.ThrowIfNull(clients);
        _clients = clients.ToFrozenDictionary(x => x.GetClientId(), x => x, StringComparer.Ordinal);
    }

    public Task<InMemoryClient?> FindEnabledAsync(
        InMemoryRequestContext requestContext,
        string clientId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_clients.TryGetValue(clientId, out var client))
        {
            return Task.FromResult<InMemoryClient?>(client);
        }

        return Task.FromResult<InMemoryClient?>(null);
    }
}
