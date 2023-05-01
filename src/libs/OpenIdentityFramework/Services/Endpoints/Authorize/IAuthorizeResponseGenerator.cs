using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<AuthorizeResponseGenerationResult> CreateResponseAsync(
        HttpContext httpContext,
        ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret> request,
        CancellationToken cancellationToken);
}
