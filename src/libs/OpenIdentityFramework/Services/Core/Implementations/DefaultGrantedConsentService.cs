using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultGrantedConsentService<TClient, TClientSecret, TGrantedConsent>
    : IGrantedConsentService<TClient, TClientSecret, TGrantedConsent>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TGrantedConsent : AbstractGrantedConsent
{
    public DefaultGrantedConsentService(IGrantedConsentStorage<TGrantedConsent> storage, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        Storage = storage;
        SystemClock = systemClock;
    }

    protected IGrantedConsentStorage<TGrantedConsent> Storage { get; }
    protected ISystemClock SystemClock { get; }

    public async Task<TGrantedConsent?> FindAsync(HttpContext httpContext, string subjectId, TClient client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();

        // if can't remember - nothing will be returned
        if (!client.CanRememberConsent())
        {
            return null;
        }

        var clientId = client.GetClientId();
        var consent = await Storage.FindAsync(httpContext, subjectId, clientId, cancellationToken);
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
                    await Storage.DeleteAsync(httpContext, subjectId, clientId, cancellationToken);
                    return null;
                }
            }

            return consent;
        }

        return null;
    }

    public async Task UpsertAsync(HttpContext httpContext, string subjectId, TClient client, IReadOnlySet<string> grantedScopes, CancellationToken cancellationToken)
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

                await Storage.UpsertAsync(httpContext, subjectId, client.GetClientId(), grantedScopes, expiresAt, cancellationToken);
            }
            else
            {
                await Storage.DeleteAsync(httpContext, subjectId, client.GetClientId(), cancellationToken);
            }
        }

        throw new NotImplementedException();
    }
}
