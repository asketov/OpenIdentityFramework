using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.Services.Operation;

namespace OpenIdentityFramework.InMemory.Services.Operation.RequestContextFactory;

public class InMemoryRequestContextFactory : IRequestContextFactory<InMemoryRequestContext>
{
    public Task<InMemoryRequestContext> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new InMemoryRequestContext(httpContext);
        return Task.FromResult(result);
    }
}
