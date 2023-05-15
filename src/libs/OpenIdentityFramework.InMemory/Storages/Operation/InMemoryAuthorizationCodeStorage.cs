using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.InMemory.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.InMemory.Storages.Operation;

public class InMemoryAuthorizationCodeStorage : IAuthorizationCodeStorage<InMemoryRequestContext, InMemoryAuthorizationCode, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>
{
    private readonly object _locker;
    private readonly Dictionary<string, InMemoryAuthorizationCode> _store;

    public InMemoryAuthorizationCodeStorage()
    {
        _store = new(StringComparer.Ordinal);
        _locker = new();
    }

    public Task<string> CreateAsync(
        InMemoryRequestContext requestContext,
        string clientId,
        InMemoryResourceOwnerEssentialClaims essentialClaims,
        IReadOnlySet<string> grantedScopes,
        string? authorizeRequestRedirectUri,
        string codeChallenge,
        string codeChallengeMethod,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var authorizationCode = new InMemoryAuthorizationCode(
            clientId,
            essentialClaims,
            grantedScopes,
            authorizeRequestRedirectUri,
            codeChallenge,
            codeChallengeMethod,
            issuedAt,
            expiresAt);
        var authorizationCodeHandle = Guid.NewGuid().ToString("N");
        lock (_locker)
        {
            while (_store.ContainsKey(authorizationCodeHandle))
            {
                authorizationCodeHandle = Guid.NewGuid().ToString("N");
            }

            _store[authorizationCodeHandle] = authorizationCode;
        }

        return Task.FromResult(authorizationCodeHandle);
    }

    public Task<InMemoryAuthorizationCode?> FindAsync(
        InMemoryRequestContext requestContext,
        string authorizationCodeHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryAuthorizationCode? foundAuthorizationCode = null;
        lock (_locker)
        {
            if (_store.TryGetValue(authorizationCodeHandle, out var authorizationCode))
            {
                foundAuthorizationCode = authorizationCode;
            }
        }

        return Task.FromResult(foundAuthorizationCode);
    }

    public Task DeleteAsync(
        InMemoryRequestContext requestContext,
        string authorizationCodeHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_locker)
        {
            _store.Remove(authorizationCodeHandle);
        }

        return Task.CompletedTask;
    }
}
