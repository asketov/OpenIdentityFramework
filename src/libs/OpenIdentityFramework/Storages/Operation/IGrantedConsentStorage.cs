using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IGrantedConsentStorage<TRequestContext, TGrantedConsent>
    where TRequestContext : class, IRequestContext
    where TGrantedConsent : AbstractGrantedConsent
{
    Task<TGrantedConsent?> FindAsync(
        TRequestContext requestContext,
        string subjectId,
        string clientId,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string subjectId,
        string clientId,
        CancellationToken cancellationToken);

    Task UpsertAsync(
        TRequestContext requestContext,
        string subjectId,
        string clientId,
        IReadOnlySet<string> grantedScopes,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken);
}
