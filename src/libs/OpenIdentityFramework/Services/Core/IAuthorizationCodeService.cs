using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AuthorizationCodeService;

namespace OpenIdentityFramework.Services.Core;

public interface IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    Task<AuthorizationCodeCreationResult> CreateAsync(
        TRequestContext requestContext,
        TClient client,
        EssentialResourceOwnerClaims essentialClaims,
        IReadOnlySet<string> grantedScopes,
        string? authorizeRequestRedirectUri,
        string codeChallenge,
        string codeChallengeMethod,
        DateTimeOffset issuedAt,
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
