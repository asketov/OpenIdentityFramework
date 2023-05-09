using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints;

public interface IEndpointHandler<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    Task<IEndpointHandlerResult> HandleAsync(TRequestContext requestContext, CancellationToken cancellationToken);
}
