using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Storages.Configuration;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultClientService<TRequestContext, TClient, TClientSecret>
    : IClientService<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultClientService(IClientStorage<TRequestContext, TClient, TClientSecret> storage)
    {
        ArgumentNullException.ThrowIfNull(storage);
        Storage = storage;
    }

    protected IClientStorage<TRequestContext, TClient, TClientSecret> Storage { get; }

    public virtual async Task<TClient?> FindAsync(TRequestContext requestContext, string clientId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var client = await Storage.FindEnabledAsync(requestContext, clientId, cancellationToken);
        if (client != null && string.Equals(clientId, client.GetClientId(), StringComparison.Ordinal))
        {
            return client;
        }

        return null;
    }
}
