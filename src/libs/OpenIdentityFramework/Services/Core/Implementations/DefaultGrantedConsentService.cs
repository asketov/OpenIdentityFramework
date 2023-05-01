using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent>
    : IGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TGrantedConsent : AbstractGrantedConsent
{
    public DefaultGrantedConsentService(IGrantedConsentStorage<TRequestContext, TGrantedConsent> storage, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        Storage = storage;
        SystemClock = systemClock;
    }

    protected IGrantedConsentStorage<TRequestContext, TGrantedConsent> Storage { get; }
    protected ISystemClock SystemClock { get; }

    public virtual async Task<TGrantedConsent?> FindAsync(
        TRequestContext requestContext,
        string subjectId,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();

        // if can't remember - nothing will be returned
        if (!client.CanRememberConsent())
        {
            return null;
        }

        var clientId = client.GetClientId();
        var consent = await Storage.FindAsync(requestContext, subjectId, clientId, cancellationToken);
        if (consent == null)
        {
            return null;
        }

        if (consent.GetClientId() == clientId && consent.GetSubjectId() == subjectId)
        {
            var expirationDate = consent.GetExpirationDate();
            if (expirationDate.HasValue)
            {
                var currentDate = SystemClock.UtcNow;
                if (currentDate > expirationDate.Value)
                {
                    await Storage.DeleteAsync(requestContext, subjectId, clientId, cancellationToken);
                    return null;
                }
            }

            return consent;
        }

        return null;
    }

    public virtual async Task UpsertAsync(
        TRequestContext requestContext,
        string subjectId,
        TClient client,
        IReadOnlySet<string> grantedScopes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(grantedScopes);
        cancellationToken.ThrowIfCancellationRequested();
        if (client.CanRememberConsent())
        {
            if (grantedScopes.Count > 0)
            {
                var consentLifetime = client.GetConsentLifetime();
                DateTimeOffset? expiresAt = null;
                if (consentLifetime.HasValue)
                {
                    var currentDate = SystemClock.UtcNow;
                    expiresAt = currentDate.Add(consentLifetime.Value);
                }

                await Storage.UpsertAsync(requestContext, subjectId, client.GetClientId(), grantedScopes, expiresAt, cancellationToken);
            }
            else
            {
                await Storage.DeleteAsync(requestContext, subjectId, client.GetClientId(), cancellationToken);
            }
        }

        throw new NotImplementedException();
    }
}
