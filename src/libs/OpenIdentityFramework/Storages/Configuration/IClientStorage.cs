using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Storages.Configuration;

public interface IClientStorage<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    Task<TClient?> FindEnabledAsync(HttpContext httpContext, string clientId, CancellationToken cancellationToken);
}
