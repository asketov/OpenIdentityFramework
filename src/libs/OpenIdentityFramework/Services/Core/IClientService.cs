using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core;

public interface IClientService<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    Task<TClient?> FindAsync(HttpContext httpContext, string clientId, CancellationToken cancellationToken);
}
