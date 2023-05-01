using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizationCodeStorage<TRequestContext, TAuthorizationCode>
    where TRequestContext : AbstractRequestContext
    where TAuthorizationCode : AbstractAuthorizationCode
{
    Task<string> CreateAsync(
        TRequestContext requestContext,
        UserAuthentication userAuthentication,
        string clientId,
        string? originalRedirectUri,
        IReadOnlySet<string> grantedScopes,
        string codeChallenge,
        string codeChallengeMethod,
        string? nonce,
        string? state,
        string issuer,
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
