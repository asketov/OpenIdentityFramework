using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizeRequestConsentStorage<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequestConsent : AbstractAuthorizeRequestConsent<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<TAuthorizeRequestConsent?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestHandle,
        TResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken);

    Task GrantAsync(
        TRequestContext requestContext,
        string authorizeRequestHandle,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentGranted grantedConsent,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    Task DenyAsync(
        TRequestContext requestContext,
        string authorizeRequestHandle,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentDenied deniedConsent,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestHandle,
        TResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken);
}
