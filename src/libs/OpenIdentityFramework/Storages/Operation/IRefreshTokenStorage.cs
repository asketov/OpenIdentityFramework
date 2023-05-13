using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IRefreshTokenStorage<TRequestContext, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        string clientId,
        TResourceOwnerEssentialClaims essentialResourceOwnerClaims,
        IReadOnlySet<string> grantedScopes,
        string? referenceAccessTokenHandle,
        string? parentRefreshTokenHandle,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        DateTimeOffset? absoluteExpiresAt);

    Task<TRefreshToken?> FindAsync(
        TRequestContext requestContext,
        string refreshTokenHandle,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string refreshTokenHandle,
        CancellationToken cancellationToken);
}
