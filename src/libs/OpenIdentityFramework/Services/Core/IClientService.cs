using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core;

public interface IClientService<TClient> where TClient : AbstractClient
{
    Task<TClient?> FindEnabledAsync(HttpContext httpContext, string clientId, CancellationToken cancellationToken);
}
