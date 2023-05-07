using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation;

public interface ITokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
    where TRefreshToken : AbstractRefreshToken
{
    Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>> ValidateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        string clientAuthenticationMethod,
        string issuer,
        CancellationToken cancellationToken);
}
