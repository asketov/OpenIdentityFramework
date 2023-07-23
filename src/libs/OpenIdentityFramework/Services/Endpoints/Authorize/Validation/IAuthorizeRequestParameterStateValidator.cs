using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Validation;

public interface IAuthorizeRequestParameterStateValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    Task<AuthorizeRequestParameterStateValidationResult> ValidateStateParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken);
}
