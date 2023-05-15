using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.InMemory.Models;

public class InMemoryRequestContext : IRequestContext
{
    public InMemoryRequestContext(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        HttpContext = httpContext;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public HttpContext HttpContext { get; }

    public Task CommitAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public Task RollbackAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    [SuppressMessage("ReSharper", "UnusedParameter.Global")]
    protected virtual void Dispose(bool disposing)
    {
    }
}
