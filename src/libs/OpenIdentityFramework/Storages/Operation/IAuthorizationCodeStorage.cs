using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Storages.Operation;

public interface IAuthorizationCodeStorage
{
    Task<string> CreateAsync(
        HttpContext httpContext,
        UserAuthentication userAuthentication,
        string clientId,
        string redirectUri,
        IReadOnlySet<string> grantedScopes,
        string codeChallenge,
        string codeChallengeMethod,
        string? nonce,
        string? state,
        string issuer,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);
}
