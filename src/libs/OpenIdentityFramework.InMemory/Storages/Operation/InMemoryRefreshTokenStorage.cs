using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.InMemory.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.InMemory.Storages.Operation;

public class InMemoryRefreshTokenStorage : IRefreshTokenStorage<InMemoryRequestContext, InMemoryRefreshToken, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>
{
    private readonly object _locker;
    private readonly Dictionary<string, InMemoryRefreshToken> _store;

    public InMemoryRefreshTokenStorage()
    {
        _store = new(StringComparer.Ordinal);
        _locker = new();
    }

    public Task<string> CreateAsync(
        InMemoryRequestContext requestContext,
        string clientId,
        InMemoryResourceOwnerEssentialClaims essentialResourceOwnerClaims,
        IReadOnlySet<string> grantedScopes,
        string? referenceAccessTokenHandle,
        string? parentRefreshTokenHandle,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        DateTimeOffset? absoluteExpiresAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var refreshToken = new InMemoryRefreshToken(
            clientId,
            essentialResourceOwnerClaims,
            grantedScopes,
            referenceAccessTokenHandle,
            parentRefreshTokenHandle,
            issuedAt,
            expiresAt,
            absoluteExpiresAt);
        var refreshTokenHandle = Guid.NewGuid().ToString("N");
        lock (_locker)
        {
            while (_store.ContainsKey(refreshTokenHandle))
            {
                refreshTokenHandle = Guid.NewGuid().ToString("N");
            }

            _store[refreshTokenHandle] = refreshToken;
        }

        return Task.FromResult(refreshTokenHandle);
    }

    public Task<InMemoryRefreshToken?> FindAsync(
        InMemoryRequestContext requestContext,
        string refreshTokenHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryRefreshToken? foundRefreshToken = null;
        lock (_locker)
        {
            if (_store.TryGetValue(refreshTokenHandle, out var refreshToken))
            {
                foundRefreshToken = refreshToken;
            }
        }

        return Task.FromResult(foundRefreshToken);
    }

    public Task DeleteAsync(
        InMemoryRequestContext requestContext,
        string refreshTokenHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_locker)
        {
            _store.Remove(refreshTokenHandle);
        }

        return Task.CompletedTask;
    }
}
