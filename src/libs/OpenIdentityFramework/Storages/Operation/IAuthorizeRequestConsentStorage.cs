using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizeRequestConsentStorage<TRequestContext, TRequestConsent>
    where TRequestContext : AbstractRequestContext
    where TRequestConsent : AbstractAuthorizeRequestConsent
{
    Task<TRequestConsent?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);

    Task GrantAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        string authorizeRequestId,
        IReadOnlySet<string> grantedScopes,
        bool remember,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    Task DenyAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        string authorizeRequestId,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);
}
