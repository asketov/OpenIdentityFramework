using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.TokenService;

namespace OpenIdentityFramework.Services.Core;

public interface ITokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<string> CreateIdTokenAsync(
        HttpContext httpContext,
        IdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> idTokenRequest,
        CancellationToken cancellationToken);

    Task<AccessTokenResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> CreateAccessTokenAsync(
        HttpContext httpContext,
        AccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> accessTokenRequest,
        CancellationToken cancellationToken);

    Task<string> CreateRefreshTokenAsync(
        HttpContext httpContext,
        RefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> refreshTokenRequest,
        CancellationToken cancellationToken);
}
