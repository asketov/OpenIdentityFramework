using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Core;

public interface IGrantedConsentService<TClient, TClientSecret, TGrantedConsent>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TGrantedConsent : AbstractGrantedConsent
{
    Task<TGrantedConsent?> FindAsync(HttpContext httpContext, string subjectId, TClient client, CancellationToken cancellationToken);

    Task UpsertAsync(HttpContext httpContext, string subjectId, TClient client, IReadOnlySet<string> grantedScopes, CancellationToken cancellationToken);
}
