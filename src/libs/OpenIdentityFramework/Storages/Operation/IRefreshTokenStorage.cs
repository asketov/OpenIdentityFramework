using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Storages.Operation;

public interface IRefreshTokenStorage<TRequestContext, TRefreshToken>
    where TRequestContext : AbstractRequestContext
    where TRefreshToken : AbstractRefreshToken
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        string issuer,
        string clientId,
        UserAuthentication? userAuthentication,
        IReadOnlySet<string> grantedScopes,
        IReadOnlySet<LightweightClaim> claims,
        string? accessTokenHandle,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        DateTimeOffset? absoluteExpirationDate,
        CancellationToken cancellationToken);

    Task<TRefreshToken?> FindAsync(
        TRequestContext requestContext,
        string refreshTokenHandle,
        string issuer,
        string clientId,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string refreshTokenHandle,
        CancellationToken cancellationToken);
}
