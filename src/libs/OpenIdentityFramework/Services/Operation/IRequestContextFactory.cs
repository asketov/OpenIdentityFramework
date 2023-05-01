using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Operation;

public interface IRequestContextFactory<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<TRequestContext> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
