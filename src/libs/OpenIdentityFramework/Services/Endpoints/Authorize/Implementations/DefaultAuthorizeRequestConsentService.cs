using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeRequestConsentService<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers>
    : IAuthorizeRequestConsentService<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequestConsent : AbstractAuthorizeRequestConsent<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultAuthorizeRequestConsentService(IAuthorizeRequestConsentStorage<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers> storage, ISystemClock systemClock)
    {
        Storage = storage;
        SystemClock = systemClock;
    }

    protected IAuthorizeRequestConsentStorage<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers> Storage { get; }
    protected ISystemClock SystemClock { get; }

    public virtual async Task<TAuthorizeRequestConsent?> FindAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var consent = await Storage.FindAsync(requestContext, authorizeRequestId, authorIdentifiers, cancellationToken);
        if (consent != null && consent.GetAuthorIdentifiers().Equals(authorIdentifiers))
        {
            var currentDate = SystemClock.UtcNow;
            var expirationDate = consent.GetExpirationDate();
            if (currentDate > expirationDate)
            {
                await DeleteAsync(requestContext, authorizeRequestId, authorIdentifiers, cancellationToken);
                return null;
            }

            return consent;
        }

        return null;
    }

    public virtual async Task DeleteAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DeleteAsync(requestContext, authorizeRequestId, authorIdentifiers, cancellationToken);
    }
}
