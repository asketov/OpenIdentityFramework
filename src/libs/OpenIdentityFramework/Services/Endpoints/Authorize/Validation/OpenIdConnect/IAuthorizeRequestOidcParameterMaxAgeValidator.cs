using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Validation.OpenIdConnect;

public interface IAuthorizeRequestOidcParameterMaxAgeValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    Task<AuthorizeRequestOidcParameterMaxAgeValidationResult> ValidateMaxAgeOidcParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken);
}
