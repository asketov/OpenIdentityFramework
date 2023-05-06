using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestConsentService<TRequestContext, TRequestConsent>
    where TRequestContext : AbstractRequestContext
    where TRequestConsent : AbstractAuthorizeRequestConsent
{
    Task GrantAsync(TRequestContext requestContext, string authorizeRequestId, IReadOnlySet<string> grantedScopes, bool remember, CancellationToken cancellationToken);

    Task DenyAsync(TRequestContext requestContext, string authorizeRequestId, CancellationToken cancellationToken);

    Task<TRequestConsent?> ReadAsync(TRequestContext requestContext, string authorizeRequestId, CancellationToken cancellationToken);
    Task DeleteAsync(TRequestContext requestContext, string authorizeRequestId, CancellationToken cancellationToken);
}
