using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;
using OpenIdentityFramework.Services.Core.Models.RefreshTokenService;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

namespace OpenIdentityFramework.Services.Core;

public interface IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<RefreshTokenCreationResult> CreateAsync(
        TRequestContext requestContext,
        string issuer,
        ValidRefreshToken<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? previousRefreshToken,
        CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> createdAccessToken,
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
