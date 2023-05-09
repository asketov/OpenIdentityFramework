using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Handlers;

public interface IJwksEndpointHandler<TRequestContext> : IEndpointHandler<TRequestContext>
    where TRequestContext : class, IRequestContext
{
}
