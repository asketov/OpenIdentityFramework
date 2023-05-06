using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Validation;

public interface IAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    Task<AuthorizeRequestParameterResponseModeValidationResult> ValidateResponseModeParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        string responseType,
        CancellationToken cancellationToken);
}
