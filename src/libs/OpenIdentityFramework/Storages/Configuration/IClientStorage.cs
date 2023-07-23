using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Storages.Configuration;

public interface IClientStorage<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    Task<TClient?> FindEnabledAsync(TRequestContext requestContext, string clientId, CancellationToken cancellationToken);
}
