using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Interaction;

public interface IOpenIdentityFrameworkInteractionService<TRequestContext, TAuthorizeRequestParameters>
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequestParameters : AbstractAuthorizeRequestParameters
{
    Task FindAuthorizationCodeAsync(HttpContext httpContext, string authorizeRequestId, CancellationToken cancellationToken);
}
