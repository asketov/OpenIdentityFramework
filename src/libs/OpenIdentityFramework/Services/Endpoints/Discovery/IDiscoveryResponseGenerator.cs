using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Endpoints.Discovery.Models.DiscoveryResponseGenerator;

namespace OpenIdentityFramework.Services.Endpoints.Discovery;

public interface IDiscoveryResponseGenerator<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    Task<DiscoveryDocument> CreateDiscoveryDocumentAsync(
        TRequestContext requestContext,
        string issuer,
        CancellationToken cancellationToken);
}
