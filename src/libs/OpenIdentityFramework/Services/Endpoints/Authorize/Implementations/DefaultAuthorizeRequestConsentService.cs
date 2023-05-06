using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeRequestConsentService<TRequestContext, TRequestConsent>
    : IAuthorizeRequestConsentService<TRequestContext, TRequestConsent>
    where TRequestContext : AbstractRequestContext
    where TRequestConsent : AbstractAuthorizeRequestConsent
{
    public DefaultAuthorizeRequestConsentService(IAuthorizeRequestConsentStorage<TRequestContext, TRequestConsent> storage, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        Storage = storage;
        SystemClock = systemClock;
    }

    protected IAuthorizeRequestConsentStorage<TRequestContext, TRequestConsent> Storage { get; }
    protected ISystemClock SystemClock { get; }

    public virtual async Task GrantAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        IReadOnlySet<string> grantedScopes,
        bool remember,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.GrantAsync(requestContext, authorizeRequestId, grantedScopes, remember, null, cancellationToken);
    }

    public virtual async Task DenyAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DenyAsync(requestContext, authorizeRequestId, null, cancellationToken);
    }

    public virtual async Task<TRequestConsent?> ReadAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var consent = await Storage.FindAsync(requestContext, authorizeRequestId, cancellationToken);
        if (consent is not null)
        {
            var expiresAt = consent.GetExpirationDate();
            if (expiresAt.HasValue && SystemClock.UtcNow > expiresAt.Value)
            {
                await Storage.DeleteAsync(requestContext, authorizeRequestId, cancellationToken);
                return null;
            }

            return consent;
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
