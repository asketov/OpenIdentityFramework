using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Handlers;

public interface IDiscoveryEndpointHandler<TRequestContext> : IEndpointHandler<TRequestContext>
    where TRequestContext : class, IRequestContext
{
}
