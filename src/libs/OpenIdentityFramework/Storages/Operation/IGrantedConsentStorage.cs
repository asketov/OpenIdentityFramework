using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IGrantedConsentStorage<TGrantedConsent>
    where TGrantedConsent : AbstractGrantedConsent
{
    Task<TGrantedConsent?> FindAsync(HttpContext httpContext, string subjectId, string clientId, CancellationToken cancellationToken);

    Task DeleteAsync(HttpContext httpContext, string subjectId, string clientId, CancellationToken cancellationToken);

    Task UpsertAsync(HttpContext httpContext, string subjectId, string clientId, IReadOnlySet<string> grantedScopes, DateTimeOffset? expiresAt, CancellationToken cancellationToken);
}
