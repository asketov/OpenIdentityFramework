using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAccessTokenStorage<TRequestContext, TAccessToken>
    where TRequestContext : AbstractRequestContext
    where TAccessToken : AbstractAccessToken
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        string issuer,
        string clientId,
        UserAuthentication? userAuthentication,
        IReadOnlySet<string> grantedScopes,
        IReadOnlySet<LightweightClaim> claims,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);
}
