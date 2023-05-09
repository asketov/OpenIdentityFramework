using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestConsentService<TRequestContext, TRequestConsent>
    where TRequestContext : class, IRequestContext
    where TRequestConsent : AbstractAuthorizeRequestConsent
{
    Task GrantAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        string authorizeRequestId,
        IReadOnlySet<string> grantedScopes,
        bool remember,
        CancellationToken cancellationToken);

    Task DenyAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        string authorizeRequestId,
        CancellationToken cancellationToken);

    Task<TRequestConsent?> ReadAsync(
        TRequestContext requestContext,
        ResourceOwnerIdentifiers resourceOwnerIdentifiers,
        string authorizeRequestId,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);
}
