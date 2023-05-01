using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints;

public interface IEndpointHandler<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<IEndpointHandlerResult<TRequestContext>> HandleAsync(TRequestContext requestContext, CancellationToken cancellationToken);
}
