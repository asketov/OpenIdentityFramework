using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ClientAuthenticationService;

namespace OpenIdentityFramework.Services.Core;

public interface IClientAuthenticationService<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    Task<ClientAuthenticationResult<TClient, TClientSecret>> AuthenticateAsync(
        HttpContext httpContext,
        IFormCollection form,
        CancellationToken cancellationToken);
}
