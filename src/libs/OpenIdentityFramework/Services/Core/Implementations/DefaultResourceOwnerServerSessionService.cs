using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Storages.Integration;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultResourceOwnerServerSessionService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    : IResourceOwnerServerSessionService<TRequestContext>
    where TRequestContext : class, IRequestContext
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultResourceOwnerServerSessionService(
        IResourceOwnerEssentialClaimsProvider<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> essentialClaimsProvider,
        IResourceOwnerServerSessionStorage<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> serverSessionStorage)
    {
        ArgumentNullException.ThrowIfNull(essentialClaimsProvider);
        ArgumentNullException.ThrowIfNull(serverSessionStorage);
        EssentialClaimsProvider = essentialClaimsProvider;
        ServerSessionStorage = serverSessionStorage;
    }

    protected IResourceOwnerEssentialClaimsProvider<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> EssentialClaimsProvider { get; }
    protected IResourceOwnerServerSessionStorage<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> ServerSessionStorage { get; }

    public async Task<string> StoreAsync(TRequestContext requestContext, AuthenticationTicket ticket, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var essentialClaimsResult = await EssentialClaimsProvider.GetAsync(requestContext, ticket, cancellationToken);
        if (essentialClaimsResult.HasError)
        {
            throw new ArgumentException(essentialClaimsResult.ErrorDescription, nameof(ticket));
        }

        return await ServerSessionStorage.StoreAsync(requestContext, ticket, essentialClaimsResult.EssentialClaims, cancellationToken);
    }

    public async Task RenewAsync(TRequestContext requestContext, string key, AuthenticationTicket ticket, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var essentialClaimsResult = await EssentialClaimsProvider.GetAsync(requestContext, ticket, cancellationToken);
        if (essentialClaimsResult.HasError)
        {
            throw new ArgumentException(essentialClaimsResult.ErrorDescription, nameof(ticket));
        }

        await ServerSessionStorage.RenewAsync(requestContext, key, ticket, essentialClaimsResult.EssentialClaims, cancellationToken);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(TRequestContext requestContext, string key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await ServerSessionStorage.RetrieveAsync(requestContext, key, cancellationToken);
    }

    public async Task RemoveAsync(TRequestContext requestContext, string key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await ServerSessionStorage.RemoveAsync(requestContext, key, cancellationToken);
    }
}
