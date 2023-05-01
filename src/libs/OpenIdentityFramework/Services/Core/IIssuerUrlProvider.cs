using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Core;

public interface IIssuerUrlProvider<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<string> GetIssuerAsync(TRequestContext requestContext, CancellationToken cancellationToken);
}
