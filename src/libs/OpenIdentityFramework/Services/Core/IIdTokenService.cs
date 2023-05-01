using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.IdTokenService;

namespace OpenIdentityFramework.Services.Core;

public interface IIdTokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<IdTokenCreationResult> CreateIdTokenAsync(
        HttpContext httpContext,
        CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createIdTokenRequest,
        CancellationToken cancellationToken);
}
