using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

public class AuthorizeRequestOidcParameterDisplayValidationResult
{
    public static readonly AuthorizeRequestOidcParameterDisplayValidationResult Null = new((string?) null);

    public static readonly AuthorizeRequestOidcParameterDisplayValidationResult Page = new(Constants.Request.Authorize.Display.Page);

    public static readonly AuthorizeRequestOidcParameterDisplayValidationResult Popup = new(Constants.Request.Authorize.Display.Popup);

    public static readonly AuthorizeRequestOidcParameterDisplayValidationResult Touch = new(Constants.Request.Authorize.Display.Touch);

    public static readonly AuthorizeRequestOidcParameterDisplayValidationResult Wap = new(Constants.Request.Authorize.Display.Wap);

    public static readonly AuthorizeRequestOidcParameterDisplayValidationResult MultipleDisplayValues = new(new ProtocolError(
        Errors.InvalidRequest,
        "Multiple \"display\" parameter values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestOidcParameterDisplayValidationResult UnsupportedDisplay = new(new ProtocolError(
        Errors.InvalidRequest,
        "Provided \"display\" is not supported"));

    public AuthorizeRequestOidcParameterDisplayValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestOidcParameterDisplayValidationResult(string? display)
    {
        Display = display;
    }

    public string? Display { get; }
    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
