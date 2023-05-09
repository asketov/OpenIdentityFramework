using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAccessTokenStorage<TRequestContext, TAccessToken>
    where TRequestContext : class, IRequestContext
    where TAccessToken : AbstractAccessToken
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        string clientId,
        EssentialResourceOwnerClaims? essentialResourceOwnerClaims,
        IReadOnlySet<string> grantedScopes,
        IReadOnlySet<LightweightClaim> claims,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string accessTokenHandle,
        CancellationToken cancellationToken);
}
