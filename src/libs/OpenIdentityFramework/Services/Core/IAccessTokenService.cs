using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;

namespace OpenIdentityFramework.Services.Core;

public interface IAccessTokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAccessToken>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAccessToken : AbstractAccessToken
{
    Task<AccessTokenCreationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> CreateAccessTokenAsync(
        HttpContext httpContext,
        CreateAccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createAccessTokenRequest,
        CancellationToken cancellationToken);

    Task DeleteAsync(HttpContext httpContext, string accessTokenHandle, CancellationToken cancellationToken);
}
