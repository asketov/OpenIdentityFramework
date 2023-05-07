using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.CommonParameters;

public class TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public static readonly TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret> MultipleScope = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "Multiple \"scope\" values are present, but only 1 has allowed"));

    public static readonly TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret> ScopeIsTooLong = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "\"scope\" parameter is too long"));

    public static readonly TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret> InvalidScopeSyntax = new(new ProtocolError(
        TokenErrors.InvalidScope,
        "Invalid \"scope\" syntax"));

    public static readonly TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret> InvalidScope = new(new ProtocolError(
        TokenErrors.InvalidScope,
        "Invalid \"scope\""));

    public static readonly TokenRequestCommonParameterScopeValidationResult<TScope, TResource, TResourceSecret> Misconfigured = new(new ProtocolError(
        TokenErrors.InvalidScope,
        "\"scope\" contains misconfigured scopes"));

    public TokenRequestCommonParameterScopeValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public TokenRequestCommonParameterScopeValidationResult(ValidResources<TScope, TResource, TResourceSecret> allowedResources)
    {
        AllowedResources = allowedResources;
    }

    public ValidResources<TScope, TResource, TResourceSecret>? AllowedResources { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(AllowedResources))]
    public bool HasError { get; }
}
