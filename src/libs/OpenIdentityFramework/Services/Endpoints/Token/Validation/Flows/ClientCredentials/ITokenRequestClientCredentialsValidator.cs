using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.ClientCredentials;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.ClientCredentials;

public interface ITokenRequestClientCredentialsValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<TokenRequestClientCredentialsValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> ValidateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        string clientAuthenticationMethod,
        CancellationToken cancellationToken);
}
