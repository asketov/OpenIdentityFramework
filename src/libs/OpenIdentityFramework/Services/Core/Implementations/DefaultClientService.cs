using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Storages.Configuration;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultClientService<TClient> : IClientService<TClient>
    where TClient : AbstractClient
{
    public DefaultClientService(IClientStorage<TClient> storage)
    {
        ArgumentNullException.ThrowIfNull(storage);
        Storage = storage;
    }

    protected IClientStorage<TClient> Storage { get; }

    public virtual async Task<TClient?> FindEnabledAsync(HttpContext httpContext, string clientId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var client = await Storage.FindEnabledAsync(httpContext, clientId, cancellationToken);
        if (client != null && client.IsEnabled() && string.Equals(clientId, client.GetClientId(), StringComparison.Ordinal))
        {
            return client;
        }

        return null;
    }
}
