using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeRequestConsentService<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequestConsent : AbstractAuthorizeRequestConsent<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<TAuthorizeRequestConsent?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken);
}
