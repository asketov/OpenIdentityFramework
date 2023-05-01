using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;

namespace OpenIdentityFramework.Services.Core;

public interface IResourceValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<ResourcesValidationResult<TScope, TResource, TResourceSecret>> ValidateRequestedScopesAsync(
        TRequestContext requestContext,
        TClient client,
        IReadOnlySet<string> requestedScopes,
        IReadOnlySet<string> allowedTokenTypesForScopes,
        CancellationToken cancellationToken);
}
