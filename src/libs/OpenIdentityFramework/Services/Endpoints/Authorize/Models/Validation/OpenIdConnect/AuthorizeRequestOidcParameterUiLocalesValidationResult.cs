using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

public class AuthorizeRequestOidcParameterUiLocalesValidationResult
{
    public static readonly AuthorizeRequestOidcParameterUiLocalesValidationResult Null = new((string?) null);

    public static readonly AuthorizeRequestOidcParameterUiLocalesValidationResult MultipleUiLocalesValues = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Multiple \"ui_locales\" parameter values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestOidcParameterUiLocalesValidationResult UiLocalesIsTooLong = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "\"ui_locales\" parameter is too long"));

    public AuthorizeRequestOidcParameterUiLocalesValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestOidcParameterUiLocalesValidationResult(string? uiLocales)
    {
        UiLocales = uiLocales;
    }

    public string? UiLocales { get; }
    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
