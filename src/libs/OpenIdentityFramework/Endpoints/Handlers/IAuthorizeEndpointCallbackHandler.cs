using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Handlers;

public interface IAuthorizeEndpointCallbackHandler<TRequestContext> : IEndpointHandler<TRequestContext>
    where TRequestContext : class, IRequestContext
{
}
