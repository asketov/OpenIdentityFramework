using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;
using OpenIdentityFramework.Services.Core.Models.RefreshTokenService;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

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
        string issuer,
        ValidRefreshToken<TRefreshToken>? previousRefreshToken,
        CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret> createdAccessToken,
        CancellationToken cancellationToken);

    Task<TRefreshToken?> FindAsync(
        TRequestContext requestContext,
        TClient client,
        string refreshTokenHandle,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string refreshTokenHandle,
        CancellationToken cancellationToken);
}
