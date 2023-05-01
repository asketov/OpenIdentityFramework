using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Results;

public interface IEndpointHandlerResult<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task ExecuteAsync(TRequestContext requestContext, CancellationToken cancellationToken);
}
