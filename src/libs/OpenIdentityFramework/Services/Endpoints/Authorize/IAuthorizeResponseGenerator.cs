using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize;

public interface IAuthorizeResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<AuthorizeResponseGenerationResult> CreateResponseAsync(
        TRequestContext requestContext,
        ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> request,
        CancellationToken cancellationToken);
}
