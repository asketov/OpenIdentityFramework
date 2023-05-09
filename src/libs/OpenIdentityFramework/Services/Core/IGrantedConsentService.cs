using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Core;

public interface IGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TGrantedConsent : AbstractGrantedConsent
{
    Task<TGrantedConsent?> FindAsync(
        TRequestContext requestContext,
        string subjectId,
        TClient client,
        CancellationToken cancellationToken);

    Task UpsertAsync(
        TRequestContext requestContext,
        string subjectId,
        TClient client,
        IReadOnlySet<string> grantedScopes,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string subjectId,
        TClient client,
        CancellationToken cancellationToken);
}
