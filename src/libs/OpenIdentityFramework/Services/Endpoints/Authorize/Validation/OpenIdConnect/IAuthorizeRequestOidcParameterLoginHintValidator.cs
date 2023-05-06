using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

public interface IAuthorizeRequestOidcParameterLoginHintValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    Task<AuthorizeRequestOidcParameterLoginHintValidationResult> ValidateLoginHintOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken);
}
