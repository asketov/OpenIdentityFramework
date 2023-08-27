using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Operation;

namespace OpenIdentityFramework.Services.Integration.Implementations;

public class OpenIdentityFrameworkTicketStore<TRequestContext> : ITicketStore
    where TRequestContext : class, IRequestContext
{
    public OpenIdentityFrameworkTicketStore(IResourceOwnerServerSessionService<TRequestContext> serverSessionService)
    {
        ArgumentNullException.ThrowIfNull(serverSessionService);
        ServerSessionService = serverSessionService;
    }

    protected IResourceOwnerServerSessionService<TRequestContext> ServerSessionService { get; }

    /// <inheritdoc />
    public virtual Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public virtual Task<string> StoreAsync(AuthenticationTicket ticket, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public virtual async Task<string> StoreAsync(AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(httpContext);
        var contextFactory = httpContext.RequestServices.GetRequiredService<IRequestContextFactory<TRequestContext>>();
        await using var requestContext = await contextFactory.CreateAsync(httpContext, cancellationToken);
        var result = await ServerSessionService.StoreAsync(requestContext, ticket, cancellationToken);
        await requestContext.CommitAsync(cancellationToken);
        return result;
    }

    /// <inheritdoc />
    public virtual Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public virtual Task RenewAsync(string key, AuthenticationTicket ticket, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public virtual async Task RenewAsync(string key, AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(httpContext);
        var contextFactory = httpContext.RequestServices.GetRequiredService<IRequestContextFactory<TRequestContext>>();
        await using var requestContext = await contextFactory.CreateAsync(httpContext, cancellationToken);
        await ServerSessionService.RenewAsync(requestContext, key, ticket, cancellationToken);
        await requestContext.CommitAsync(cancellationToken);
    }

    /// <inheritdoc />
    public virtual Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public virtual Task<AuthenticationTicket?> RetrieveAsync(string key, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public virtual async Task<AuthenticationTicket?> RetrieveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(httpContext);
        var contextFactory = httpContext.RequestServices.GetRequiredService<IRequestContextFactory<TRequestContext>>();
        await using var requestContext = await contextFactory.CreateAsync(httpContext, cancellationToken);
        var result = await ServerSessionService.RetrieveAsync(requestContext, key, cancellationToken);
        await requestContext.CommitAsync(cancellationToken);
        return result;
    }

    /// <inheritdoc />
    public virtual Task RemoveAsync(string key)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public virtual Task RemoveAsync(string key, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    public virtual async Task RemoveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(httpContext);
        var contextFactory = httpContext.RequestServices.GetRequiredService<IRequestContextFactory<TRequestContext>>();
        await using var requestContext = await contextFactory.CreateAsync(httpContext, cancellationToken);
        await ServerSessionService.RemoveAsync(requestContext, key, cancellationToken);
        await requestContext.CommitAsync(cancellationToken);
    }
}
