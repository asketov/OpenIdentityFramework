using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AuthorizationCodeService;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    : IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultAuthorizationCodeService(IAuthorizationCodeStorage<TRequestContext, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> storage, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        Storage = storage;
        SystemClock = systemClock;
    }

    protected IAuthorizationCodeStorage<TRequestContext, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> Storage { get; }
    protected ISystemClock SystemClock { get; }

    public virtual async Task<AuthorizationCodeCreationResult> CreateAsync(
        TRequestContext requestContext,
        TClient client,
        TResourceOwnerEssentialClaims essentialClaims,
        IReadOnlySet<string> grantedScopes,
        string? authorizeRequestRedirectUri,
        string codeChallenge,
        string codeChallengeMethod,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(essentialClaims);
        cancellationToken.ThrowIfCancellationRequested();
        var roundIssuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAt.ToUnixTimeSeconds());
        var roundExpiresAt = DateTimeOffset.FromUnixTimeSeconds(roundIssuedAt.Add(client.GetAuthorizationCodeLifetime()).ToUnixTimeSeconds());
        var handle = await Storage.CreateAsync(
            requestContext,
            client.GetClientId(),
            essentialClaims,
            grantedScopes,
            authorizeRequestRedirectUri,
            codeChallenge,
            codeChallengeMethod,
            roundIssuedAt,
            roundExpiresAt,
            cancellationToken);
        return new(handle, roundIssuedAt, roundExpiresAt);
    }

    public virtual async Task<TAuthorizationCode?> FindAsync(TRequestContext requestContext, string authorizationCode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var code = await Storage.FindAsync(requestContext, authorizationCode, cancellationToken);
        if (code != null)
        {
            var expiresAt = code.GetExpirationDate();
            if (SystemClock.UtcNow < expiresAt)
            {
                return code;
            }

            await Storage.DeleteAsync(requestContext, authorizationCode, cancellationToken);
        }

        return null;
    }

    public virtual async Task DeleteAsync(TRequestContext requestContext, string authorizationCode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DeleteAsync(requestContext, authorizationCode, cancellationToken);
    }
}
