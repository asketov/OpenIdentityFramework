using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace OpenIdentityFramework.Models;

public abstract class AbstractRequestContext : IAsyncDisposable
{
    protected AbstractRequestContext(HttpContext httpContext)
    {
        HttpContext = httpContext;
    }

    public HttpContext HttpContext { get; }
    public abstract ValueTask DisposeAsync();
    public abstract Task CommitAsync(CancellationToken cancellationToken);
    public abstract Task RollbackAsync(CancellationToken cancellationToken);
}
