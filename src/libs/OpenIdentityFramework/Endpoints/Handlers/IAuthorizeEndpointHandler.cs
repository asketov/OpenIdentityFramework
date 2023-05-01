using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Handlers;

public interface IAuthorizeEndpointHandler<TRequestContext> : IEndpointHandler<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
}
