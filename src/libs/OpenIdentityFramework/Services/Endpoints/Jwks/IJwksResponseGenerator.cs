using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Endpoints.Jwks.Model;

namespace OpenIdentityFramework.Services.Endpoints.Jwks;

public interface IJwksResponseGenerator<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    Task<JwkSetMetadata> CreateJwkSetAsync(TRequestContext requestContext, CancellationToken cancellationToken);
}
