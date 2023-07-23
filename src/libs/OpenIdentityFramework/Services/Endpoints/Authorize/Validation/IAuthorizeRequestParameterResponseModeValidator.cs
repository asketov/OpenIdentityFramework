using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Validation;

public interface IAuthorizeRequestParameterResponseModeValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    Task<AuthorizeRequestParameterResponseModeValidationResult> ValidateResponseModeParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        IReadOnlySet<string> responseType,
        CancellationToken cancellationToken);
}
