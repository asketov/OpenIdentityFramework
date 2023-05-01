using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.IdTokenService;

namespace OpenIdentityFramework.Services.Core;

public interface IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<IdTokenCreationResult> CreateIdTokenAsync(
        TRequestContext requestContext,
        CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createIdTokenRequest,
        CancellationToken cancellationToken);
}
