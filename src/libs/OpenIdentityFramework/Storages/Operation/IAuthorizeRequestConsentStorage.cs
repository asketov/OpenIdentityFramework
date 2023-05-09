using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizeRequestConsentStorage<TRequestContext, TAuthorizeRequestConsent>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequestConsent : AbstractAuthorizeRequestConsent
{
    Task<TAuthorizeRequestConsent?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        ResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken);

    Task GrantAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        ResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentGranted grantedConsent,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken);

    Task DenyAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        ResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentDenied deniedConsent,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        ResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken);
}
