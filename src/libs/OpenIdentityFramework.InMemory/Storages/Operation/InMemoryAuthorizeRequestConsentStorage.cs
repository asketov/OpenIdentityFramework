using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.InMemory.Models.Operation;
using OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.InMemory.Storages.Operation;

public class InMemoryAuthorizeRequestConsentStorage : IAuthorizeRequestConsentStorage<InMemoryRequestContext, InMemoryAuthorizeRequestConsent, InMemoryResourceOwnerIdentifiers>
{
    private readonly IEqualityComparer<InMemoryResourceOwnerIdentifiers> _identifiersEqualityComparer;
    private readonly object _locker;
    private readonly Dictionary<string, InMemoryAuthorizeRequestConsent> _store;

    public InMemoryAuthorizeRequestConsentStorage(IEqualityComparer<InMemoryResourceOwnerIdentifiers> identifiersEqualityComparer)
    {
        ArgumentNullException.ThrowIfNull(identifiersEqualityComparer);
        _identifiersEqualityComparer = identifiersEqualityComparer;
        _store = new(StringComparer.Ordinal);
        _locker = new();
    }

    public Task<InMemoryAuthorizeRequestConsent?> FindAsync(
        InMemoryRequestContext requestContext,
        string authorizeRequestHandle,
        InMemoryResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryAuthorizeRequestConsent? foundConsent = null;
        lock (_locker)
        {
            if (_store.TryGetValue(authorizeRequestHandle, out var authorizeRequestConsent))
            {
                foundConsent = authorizeRequestConsent;
            }
        }

        return Task.FromResult(foundConsent);
    }

    public Task GrantAsync(
        InMemoryRequestContext requestContext,
        string authorizeRequestHandle,
        InMemoryResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentGranted grantedConsent,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var consent = new InMemoryAuthorizeRequestConsent(
            authorIdentifiers,
            grantedConsent,
            createdAt,
            expiresAt);
        lock (_locker)
        {
            _store[authorizeRequestHandle] = consent;
        }

        return Task.CompletedTask;
    }

    public Task DenyAsync(
        InMemoryRequestContext requestContext,
        string authorizeRequestHandle,
        InMemoryResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentDenied deniedConsent,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        var consent = new InMemoryAuthorizeRequestConsent(
            authorIdentifiers,
            deniedConsent,
            createdAt,
            expiresAt);
        lock (_locker)
        {
            _store[authorizeRequestHandle] = consent;
        }

        return Task.CompletedTask;
    }

    public Task DeleteAsync(
        InMemoryRequestContext requestContext,
        string authorizeRequestHandle,
        InMemoryResourceOwnerIdentifiers authorIdentifiers,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_locker)
        {
            if (_store.TryGetValue(authorizeRequestHandle, out var authorizeRequestConsent))
            {
                if (_identifiersEqualityComparer.Equals(authorizeRequestConsent.AuthorIdentifiers, authorIdentifiers))
                {
                    _store.Remove(authorizeRequestHandle);
                }
            }
        }

        return Task.CompletedTask;
    }
}
