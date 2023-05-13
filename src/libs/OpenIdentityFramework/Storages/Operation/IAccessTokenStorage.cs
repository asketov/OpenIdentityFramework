using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAccessTokenStorage<TRequestContext, TAccessToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TAccessToken : AbstractAccessToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        string clientId,
        TResourceOwnerEssentialClaims? essentialResourceOwnerClaims,
        IReadOnlySet<string> grantedScopes,
        IReadOnlySet<LightweightClaim> claims,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    Task<TAccessToken?> FindAsync(
        TRequestContext requestContext,
        string accessTokenHandle,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string accessTokenHandle,
        CancellationToken cancellationToken);
}
