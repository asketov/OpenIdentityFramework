using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Configuration;
using OpenIdentityFramework.Storages.Configuration;

namespace OpenIdentityFramework.InMemory.Storages.Configuration;

public class InMemoryClientStorage : IClientStorage<InMemoryRequestContext, InMemoryClient, InMemoryClientSecret>
{
    private readonly List<InMemoryClient> _clients;

    public InMemoryClientStorage(IEnumerable<InMemoryClient> clients)
    {
        ArgumentNullException.ThrowIfNull(clients);
        _clients = clients.ToList();
    }

    public Task<InMemoryClient?> FindEnabledAsync(
        InMemoryRequestContext requestContext,
        string clientId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = _clients.FirstOrDefault(x => x.ClientId == clientId);
        return Task.FromResult(result);
    }
}
