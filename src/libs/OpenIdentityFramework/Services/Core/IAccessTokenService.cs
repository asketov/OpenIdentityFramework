using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;

namespace OpenIdentityFramework.Services.Core;

public interface IAccessTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAccessToken : AbstractAccessToken
{
    Task<AccessTokenCreationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> CreateAccessTokenAsync(
        TRequestContext requestContext,
        CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createAccessTokenRequest,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string accessTokenHandle,
        CancellationToken cancellationToken);
}
