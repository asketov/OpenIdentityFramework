using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

public class AuthorizeRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
{
    public AuthorizeRequestValidationResult(ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> validRequest)
    {
        ArgumentNullException.ThrowIfNull(validRequest);
        HasError = false;
        ValidRequest = validRequest;
    }

    public AuthorizeRequestValidationResult(AuthorizeRequestValidationError<TClient, TClientSecret> validationError)
    {
        ArgumentNullException.ThrowIfNull(validationError);
        HasError = true;
        ValidationError = validationError;
    }

    public ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>? ValidRequest { get; }

    public AuthorizeRequestValidationError<TClient, TClientSecret>? ValidationError { get; }

    [MemberNotNullWhen(true, nameof(ValidationError))]
    [MemberNotNullWhen(false, nameof(ValidRequest))]
    public bool HasError { get; }
}
