using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

public class AuthorizeRequestOidcParameterLoginHintValidationResult
{
    public static readonly AuthorizeRequestOidcParameterLoginHintValidationResult Null = new((string?) null);

    public static readonly AuthorizeRequestOidcParameterLoginHintValidationResult MultipleLoginHint = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Multiple \"login_hint\" parameter values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestOidcParameterLoginHintValidationResult LoginHintIsTooLong = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "\"login_hint\" parameter is too long"));

    public AuthorizeRequestOidcParameterLoginHintValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestOidcParameterLoginHintValidationResult(string? loginHint)
    {
        LoginHint = loginHint;
    }

    public string? LoginHint { get; }
    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
