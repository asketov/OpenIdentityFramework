using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ClientAuthenticationService;

namespace OpenIdentityFramework.Services.Core;

public interface IClientAuthenticationService<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    Task<ClientAuthenticationResult<TClient, TClientSecret>> AuthenticateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        CancellationToken cancellationToken);

    Task<IReadOnlySet<string>> GetSupportedAuthenticationMethodsAsync(
        TRequestContext requestContext,
        CancellationToken cancellationToken);
}
