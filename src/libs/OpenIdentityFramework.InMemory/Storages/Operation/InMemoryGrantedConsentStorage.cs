using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.InMemory.Storages.Operation;

public class InMemoryGrantedConsentStorage : IGrantedConsentStorage<InMemoryRequestContext, InMemoryGrantedConsent>
{
    private readonly object _locker;
    private readonly Dictionary<CompositeKey, InMemoryGrantedConsent> _store;

    public InMemoryGrantedConsentStorage()
    {
        _store = new(CompositeKey.EqualityComparer);
        _locker = new();
    }

    public Task<InMemoryGrantedConsent?> FindAsync(
        InMemoryRequestContext requestContext,
        string subjectId,
        string clientId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryGrantedConsent? foundGrantedConsent = null;
        var compositeKey = new CompositeKey(subjectId, clientId);
        lock (_locker)
        {
            if (_store.TryGetValue(compositeKey, out var grantedConsent))
            {
                foundGrantedConsent = grantedConsent;
            }
        }

        return Task.FromResult(foundGrantedConsent);
    }

    public Task DeleteAsync(
        InMemoryRequestContext requestContext,
        string subjectId,
        string clientId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var compositeKey = new CompositeKey(subjectId, clientId);
        lock (_locker)
        {
            _store.Remove(compositeKey);
        }

        return Task.CompletedTask;
    }

    public Task UpsertAsync(
        InMemoryRequestContext requestContext,
        string subjectId,
        string clientId,
        IReadOnlySet<string> grantedScopes,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grantedScopes);
        cancellationToken.ThrowIfCancellationRequested();
        var compositeKey = new CompositeKey(subjectId, clientId);
        if (grantedScopes.Count == 0)
        {
            lock (_locker)
            {
                _store.Remove(compositeKey);
            }

            return Task.CompletedTask;
        }

        var grantedConsent = new InMemoryGrantedConsent(
            subjectId,
            clientId,
            grantedScopes,
            createdAt,
            expiresAt);
        lock (_locker)
        {
            _store[compositeKey] = grantedConsent;
        }

        return Task.CompletedTask;
    }

    protected sealed class CompositeKey : IEquatable<CompositeKey>
    {
        public CompositeKey(string subjectId, string clientId)
        {
            SubjectId = subjectId;
            ClientId = clientId;
        }

        public static IEqualityComparer<CompositeKey> EqualityComparer { get; } = new CompositeKeyEqualityComparer();

        public string SubjectId { get; }
        public string ClientId { get; }

        public bool Equals(CompositeKey? other)
        {
            if (ReferenceEquals(null, other))
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return SubjectId == other.SubjectId && ClientId == other.ClientId;
        }

        public override bool Equals(object? obj)
        {
            if (ReferenceEquals(null, obj))
            {
                return false;
            }

            if (ReferenceEquals(this, obj))
            {
                return true;
            }

            if (obj.GetType() != GetType())
            {
                return false;
            }

            return Equals((CompositeKey) obj);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(SubjectId, ClientId);
        }

        public static bool operator ==(CompositeKey? left, CompositeKey? right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(CompositeKey? left, CompositeKey? right)
        {
            return !Equals(left, right);
        }
    }

    protected sealed class CompositeKeyEqualityComparer : IEqualityComparer<CompositeKey>
    {
        public bool Equals(CompositeKey? x, CompositeKey? y)
        {
            if (ReferenceEquals(x, y))
            {
                return true;
            }

            if (ReferenceEquals(x, null))
            {
                return false;
            }

            if (ReferenceEquals(y, null))
            {
                return false;
            }

            if (x.GetType() != y.GetType())
            {
                return false;
            }

            return x.SubjectId == y.SubjectId && x.ClientId == y.ClientId;
        }

        public int GetHashCode(CompositeKey? obj)
        {
            return HashCode.Combine(obj?.SubjectId, obj?.ClientId);
        }
    }
}
