using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeRequestConsentService<TRequestContext, TRequestConsent>
    : IAuthorizeRequestConsentService<TRequestContext, TRequestConsent>
    where TRequestContext : AbstractRequestContext
    where TRequestConsent : AbstractAuthorizeRequestConsent
{
    public DefaultAuthorizeRequestConsentService(
        OpenIdentityFrameworkOptions frameworkOptions,
        ISystemClock systemClock,
        IAuthorizeRequestConsentStorage<TRequestContext, TRequestConsent> storage)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(storage);
        FrameworkOptions = frameworkOptions;
        SystemClock = systemClock;
        Storage = storage;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected ISystemClock SystemClock { get; }
    protected IAuthorizeRequestConsentStorage<TRequestContext, TRequestConsent> Storage { get; }

    public virtual async Task GrantAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        string authorizeRequestId,
        IReadOnlySet<string> grantedScopes,
        bool remember,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(SystemClock.UtcNow.ToUnixTimeSeconds());
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(issuedAt.Add(FrameworkOptions.UserConsentApprovalLifetime).ToUnixTimeSeconds());
        await Storage.GrantAsync(requestContext, resourceOwnerIdentifiers, authorizeRequestId, grantedScopes, remember, issuedAt, expiresAt, cancellationToken);
    }

    public virtual async Task DenyAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        string authorizeRequestId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(SystemClock.UtcNow.ToUnixTimeSeconds());
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(issuedAt.Add(FrameworkOptions.UserConsentApprovalLifetime).ToUnixTimeSeconds());
        await Storage.DenyAsync(requestContext, resourceOwnerIdentifiers, authorizeRequestId, issuedAt, expiresAt, cancellationToken);
    }

    public virtual async Task<TRequestConsent?> ReadAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        string authorizeRequestId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resourceOwnerIdentifiers);
        cancellationToken.ThrowIfCancellationRequested();
        var consent = await Storage.FindAsync(requestContext, authorizeRequestId, cancellationToken);
        if (consent is not null)
        {
            var expiresAt = consent.GetExpirationDate();
            if (expiresAt.HasValue && SystemClock.UtcNow > expiresAt.Value)
            {
                await DeleteAsync(requestContext, authorizeRequestId, cancellationToken);
                return null;
            }

            var consentIdentifiers = consent.GetResourceOwnerIdentifiers();
            if (consentIdentifiers.Equals(resourceOwnerIdentifiers))
            {
                return consent;
            }
        }

        return null;
    }

    public virtual async Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DeleteAsync(requestContext, authorizeRequestId, cancellationToken);
    }
}
