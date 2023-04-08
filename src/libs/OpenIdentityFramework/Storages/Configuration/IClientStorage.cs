using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Storages.Configuration;

public interface IClientStorage<TClient> where TClient : AbstractClient
{
    Task<TClient?> FindEnabledAsync(HttpContext httpContext, string clientId, CancellationToken cancellationToken);
}
