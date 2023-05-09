using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IRefreshTokenStorage<TRequestContext, TRefreshToken>
    where TRequestContext : class, IRequestContext
    where TRefreshToken : AbstractRefreshToken
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        string clientId,
        EssentialResourceOwnerClaims? essentialResourceOwnerClaims,
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
