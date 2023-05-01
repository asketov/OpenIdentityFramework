using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.RefreshTokenService;

namespace OpenIdentityFramework.Services.Core;

public interface IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRefreshToken : AbstractRefreshToken
{
    Task<RefreshTokenCreationResult> CreateAsync(
        TRequestContext requestContext,
        CreateRefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> createRequest,
        CancellationToken cancellationToken);

    Task<TRefreshToken?> FindAsync(
        TRequestContext requestContext,
        TClient client,
        string issuer,
        string refreshTokenHandle,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string refreshTokenHandle,
        CancellationToken cancellationToken);
}
