using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;

namespace OpenIdentityFramework.Services.Core;

public interface IResourceValidator<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<ResourcesValidationResult<TScope, TResource, TResourceSecret>> ValidateRequestedScopesAsync(
        HttpContext httpContext,
        TClient client,
        IReadOnlySet<string> requestedScopes,
        IReadOnlySet<string> allowedTokenTypesForScopes,
        CancellationToken cancellationToken);
}
