using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.CommonParameters;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation.CommonParameters;

public interface ITokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>> ValidateScopeAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        IReadOnlySet<string> grantedScopes,
        CancellationToken cancellationToken);
}
