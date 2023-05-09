using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;

namespace OpenIdentityFramework.Services.Core;

public interface IResourceOwnerAuthenticationService<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    Task<ResourceOwnerAuthenticationResult> AuthenticateAsync(TRequestContext requestContext, CancellationToken cancellationToken);
}
