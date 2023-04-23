using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestConsentService<TRequestConsent>
    where TRequestConsent : AbstractAuthorizeRequestConsent
{
    Task GrantAsync(HttpContext httpContext, string authorizeRequestId, IReadOnlySet<string> grantedScopes, bool remember, CancellationToken cancellationToken);

    Task DenyAsync(HttpContext httpContext, string authorizeRequestId, CancellationToken cancellationToken);

    Task<TRequestConsent> ReadAsync(HttpContext httpContext, string authorizeRequestId, CancellationToken cancellationToken);
    Task DeleteAsync(HttpContext httpContext, string authorizeRequestId, CancellationToken cancellationToken);
}
