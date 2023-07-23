using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent>
    : IGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TGrantedConsent : AbstractGrantedConsent
{
    public DefaultGrantedConsentService(IGrantedConsentStorage<TRequestContext, TGrantedConsent> storage, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(timeProvider);
        Storage = storage;
        TimeProvider = timeProvider;
    }

    protected IGrantedConsentStorage<TRequestContext, TGrantedConsent> Storage { get; }
    protected TimeProvider TimeProvider { get; }

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
                var currentDate = TimeProvider.GetUtcNow();
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
        if (!client.CanRememberConsent())
        {
            return;
        }

        if (grantedScopes.Count > 0)
        {
            var consentLifetime = client.GetConsentLifetime();
            var currentDate = DateTimeOffset.FromUnixTimeSeconds(TimeProvider.GetUtcNow().ToUnixTimeSeconds());
            DateTimeOffset? expiresAt = null;
            if (consentLifetime.HasValue)
            {
                expiresAt = currentDate.Add(TimeSpan.FromSeconds(consentLifetime.Value));
            }

            await Storage.UpsertAsync(requestContext, subjectId, client.GetClientId(), grantedScopes, currentDate, expiresAt, cancellationToken);
        }
        else
        {
            await Storage.DeleteAsync(requestContext, subjectId, client.GetClientId(), cancellationToken);
        }
    }

    public virtual async Task DeleteAsync(TRequestContext requestContext, string subjectId, TClient client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DeleteAsync(requestContext, subjectId, client.GetClientId(), cancellationToken);
    }
}
