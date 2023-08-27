using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.Storages.Integration;

namespace OpenIdentityFramework.InMemory.Storages.Integration;

public class InMemoryResourceOwnerServerSessionStorage
    : IResourceOwnerServerSessionStorage<InMemoryRequestContext, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>
{
    public InMemoryResourceOwnerServerSessionStorage(
        IOptions<InMemoryResourceOwnerServerSessionStorageOptions> options,
        TimeProvider timeProvider,
        IDataSerializer<AuthenticationTicket> serializer,
        IMemoryCache memoryCache)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(serializer);
        ArgumentNullException.ThrowIfNull(memoryCache);
        var optionsValue = options.Value;
        DefaultServerSessionDuration = optionsValue.DefaultServerSessionDuration;
        TimeProvider = timeProvider;
        Serializer = serializer;
        MemoryCache = memoryCache;
    }

    protected TimeSpan DefaultServerSessionDuration { get; }
    protected TimeProvider TimeProvider { get; }
    protected IDataSerializer<AuthenticationTicket> Serializer { get; }
    protected IMemoryCache MemoryCache { get; }

    public Task<string> StoreAsync(
        InMemoryRequestContext requestContext,
        AuthenticationTicket ticket,
        InMemoryResourceOwnerEssentialClaims resourceOwnerEssentialClaims,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(ticket);
        ArgumentNullException.ThrowIfNull(resourceOwnerEssentialClaims);
        var resourceOwnerIdentifiers = resourceOwnerEssentialClaims.GetResourceOwnerIdentifiers();
        var sessionId = resourceOwnerIdentifiers.GetSessionId();
        var expiresAt = ticket.Properties.ExpiresUtc ?? TimeProvider.GetUtcNow().Add(DefaultServerSessionDuration);
        var serializedTicket = Serializer.Serialize(ticket);
        MemoryCache.Set(sessionId, serializedTicket, expiresAt);
        return Task.FromResult(sessionId);
    }

    public Task RenewAsync(
        InMemoryRequestContext requestContext,
        string key,
        AuthenticationTicket ticket,
        InMemoryResourceOwnerEssentialClaims resourceOwnerEssentialClaims,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(ticket);
        ArgumentNullException.ThrowIfNull(resourceOwnerEssentialClaims);
        var sessionId = key;
        var expiresAt = ticket.Properties.ExpiresUtc ?? TimeProvider.GetUtcNow().Add(DefaultServerSessionDuration);
        var serializedTicket = Serializer.Serialize(ticket);
        MemoryCache.Set(sessionId, serializedTicket, expiresAt);
        return Task.FromResult(sessionId);
    }

    public Task<AuthenticationTicket?> RetrieveAsync(
        InMemoryRequestContext requestContext,
        string key,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (MemoryCache.TryGetValue<byte[]>(key, out var serializedTicket) && serializedTicket is not null)
        {
            var ticket = Serializer.Deserialize(serializedTicket);
            return Task.FromResult(ticket);
        }

        return Task.FromResult<AuthenticationTicket?>(null);
    }

    public Task RemoveAsync(
        InMemoryRequestContext requestContext,
        string key,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        MemoryCache.Remove(key);
        return Task.CompletedTask;
    }
}
