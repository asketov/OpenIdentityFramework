using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Endpoints.Results;

namespace OpenIdentityFramework.Endpoints;

public interface IEndpointHandler
{
    Task<IEndpointHandlerResult> HandleAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
