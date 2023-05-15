using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.InMemory.Models.Operation;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.InMemory.Storages.Operation;

public class InMemoryAccessTokenStorage : IAccessTokenStorage<InMemoryRequestContext, InMemoryAccessToken, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>
{
    private readonly object _locker;
    private readonly Dictionary<string, InMemoryAccessToken> _store;

    public InMemoryAccessTokenStorage()
    {
        _store = new(StringComparer.Ordinal);
        _locker = new();
    }

    public Task<string> CreateAsync(
        InMemoryRequestContext requestContext,
        string clientId,
        InMemoryResourceOwnerEssentialClaims? essentialResourceOwnerClaims,
        IReadOnlySet<string> grantedScopes,
        IReadOnlySet<LightweightClaim> claims,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var accessToken = new InMemoryAccessToken(
            clientId,
            essentialResourceOwnerClaims,
            grantedScopes,
            claims,
            issuedAt,
            expiresAt);
        var accessTokenHandle = Guid.NewGuid().ToString("N");
        lock (_locker)
        {
            while (_store.ContainsKey(accessTokenHandle))
            {
                accessTokenHandle = Guid.NewGuid().ToString("N");
            }

            _store[accessTokenHandle] = accessToken;
        }

        return Task.FromResult(accessTokenHandle);
    }

    public Task<InMemoryAccessToken?> FindAsync(
        InMemoryRequestContext requestContext,
        string accessTokenHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryAccessToken? foundAccessToken = null;
        lock (_locker)
        {
            if (_store.TryGetValue(accessTokenHandle, out var accessToken))
            {
                foundAccessToken = accessToken;
            }
        }

        return Task.FromResult(foundAccessToken);
    }

    public Task DeleteAsync(
        InMemoryRequestContext requestContext,
        string accessTokenHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_locker)
        {
            _store.Remove(accessTokenHandle);
        }

        return Task.CompletedTask;
    }
}
