using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
{
    public static readonly AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret> ScopeIsMissing = new(new ProtocolError(
        AuthorizeErrors.InvalidScope,
        "\"scope\" is missing"));

    public static readonly AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret> MultipleScope = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Multiple \"scope\" values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret> ScopeIsTooLong = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "\"scope\" parameter is too long"));

    public static readonly AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret> InvalidScopeSyntax = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Invalid \"scope\" syntax"));

    public static readonly AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret> InvalidScope = new(new ProtocolError(
        AuthorizeErrors.InvalidScope,
        "Invalid \"scope\""));

    public static readonly AuthorizeRequestParameterScopeValidationResult<TScope, TResource, TResourceSecret> Misconfigured = new(new ProtocolError(
        AuthorizeErrors.ServerError,
        "\"scope\" contains misconfigured scopes"));

    public AuthorizeRequestParameterScopeValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestParameterScopeValidationResult(ValidResources<TScope, TResource, TResourceSecret> validResources)
    {
        ValidResources = validResources;
    }

    public ValidResources<TScope, TResource, TResourceSecret>? ValidResources { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(ValidResources))]
    public bool HasError { get; }
}
