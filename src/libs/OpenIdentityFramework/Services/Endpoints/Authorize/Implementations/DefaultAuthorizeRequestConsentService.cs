using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeRequestConsentService<TRequestContext, TRequestConsent>
    : IAuthorizeRequestConsentService<TRequestContext, TRequestConsent>
    where TRequestContext : AbstractRequestContext
    where TRequestConsent : AbstractAuthorizeRequestConsent
{
    public Task GrantAsync(TRequestContext requestContext, string authorizeRequestId, IReadOnlySet<string> grantedScopes, bool remember, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task DenyAsync(TRequestContext requestContext, string authorizeRequestId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<TRequestConsent> ReadAsync(TRequestContext requestContext, string authorizeRequestId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task DeleteAsync(TRequestContext requestContext, string authorizeRequestId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
