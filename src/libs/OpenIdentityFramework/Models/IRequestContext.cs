using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace OpenIdentityFramework.Models;

public interface IRequestContext : IDisposable, IAsyncDisposable
{
    public HttpContext HttpContext { get; }
    public Task CommitAsync(CancellationToken cancellationToken);
    public Task RollbackAsync(CancellationToken cancellationToken);
}
