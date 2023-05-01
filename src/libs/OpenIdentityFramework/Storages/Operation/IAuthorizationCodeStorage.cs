using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizationCodeStorage<TAuthorizationCode>
    where TAuthorizationCode : AbstractAuthorizationCode
{
    Task<string> CreateAsync(
        HttpContext httpContext,
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
        HttpContext httpContext,
        string authorizationCode,
        CancellationToken cancellationToken);

    Task DeleteAsync(
        HttpContext httpContext,
        string authorizationCode,
        CancellationToken cancellationToken);
}
