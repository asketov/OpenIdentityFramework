using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Storages.Configuration;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultClientService<TClient, TClientSecret> : IClientService<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultClientService(IClientStorage<TClient, TClientSecret> storage)
    {
        ArgumentNullException.ThrowIfNull(storage);
        Storage = storage;
    }

    protected IClientStorage<TClient, TClientSecret> Storage { get; }

    public virtual async Task<TClient?> FindAsync(HttpContext httpContext, string clientId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var client = await Storage.FindEnabledAsync(httpContext, clientId, cancellationToken);
        if (client != null && string.Equals(clientId, client.GetClientId(), StringComparison.Ordinal))
        {
            return client;
        }

        return null;
    }
}
