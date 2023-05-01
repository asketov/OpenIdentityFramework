using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Handlers;

public interface ITokenEndpointHandler<TRequestContext> : IEndpointHandler<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
}
