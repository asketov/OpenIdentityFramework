using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizationCodeStorage<TRequestContext, TAuthorizationCode>
    where TRequestContext : AbstractRequestContext
    where TAuthorizationCode : AbstractAuthorizationCode
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        string clientId,
        EssentialResourceOwnerClaims essentialClaims,
        IReadOnlySet<string> grantedScopes,
        string? authorizeRequestRedirectUri,
        string codeChallenge,
        string codeChallengeMethod,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    Task<TAuthorizationCode?> FindAsync(
        TRequestContext requestContext,
        string authorizationCode,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        TRequestContext requestContext,
        string authorizationCode,
        CancellationToken cancellationToken);
}
