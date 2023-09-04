using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
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
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultAuthorizationCodeService(
        IAuthorizationCodeStorage<TRequestContext, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> storage,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(timeProvider);
        Storage = storage;
        TimeProvider = timeProvider;
    }

    protected IAuthorizationCodeStorage<TRequestContext, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> Storage { get; }
    protected TimeProvider TimeProvider { get; }

    public virtual async Task<AuthorizationCodeCreationResult> CreateAsync(
        TRequestContext requestContext,
        TClient client,
        TResourceOwnerEssentialClaims essentialClaims,
        IReadOnlySet<string> grantedScopes,
        string codeChallenge,
        string codeChallengeMethod,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(essentialClaims);
        cancellationToken.ThrowIfCancellationRequested();
        var roundIssuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAt.ToUnixTimeSeconds());
        var roundExpiresAt = DateTimeOffset.FromUnixTimeSeconds(roundIssuedAt.Add(TimeSpan.FromSeconds(client.GetAuthorizationCodeLifetime())).ToUnixTimeSeconds());
        var handle = await Storage.CreateAsync(
            requestContext,
            client.GetClientId(),
            essentialClaims,
            grantedScopes,
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
            if (TimeProvider.GetUtcNow() < expiresAt)
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
