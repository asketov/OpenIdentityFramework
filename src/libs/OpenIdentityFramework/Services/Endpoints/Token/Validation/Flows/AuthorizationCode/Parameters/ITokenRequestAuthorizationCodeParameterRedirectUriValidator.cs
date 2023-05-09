using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode.Parameters;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode.Parameters;

public interface ITokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    Task<TokenRequestAuthorizationCodeParameterRedirectUriValidationResult> ValidateRedirectUriAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        TAuthorizationCode authorizationCode,
        CancellationToken cancellationToken);
}
