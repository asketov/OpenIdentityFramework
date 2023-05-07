using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode.Parameters;

public class TokenRequestAuthorizationCodeParameterRedirectUriValidationResult
{
    public static readonly TokenRequestAuthorizationCodeParameterRedirectUriValidationResult Null = new((string?) null);

    public static readonly TokenRequestAuthorizationCodeParameterRedirectUriValidationResult RedirectUriIsMissing = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "\"redirect_uri\" is missing"));

    public static readonly TokenRequestAuthorizationCodeParameterRedirectUriValidationResult MultipleRedirectUriValuesNotAllowed = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "Multiple \"redirect_uri\" values are present, but only one is allowed"));

    public static readonly TokenRequestAuthorizationCodeParameterRedirectUriValidationResult RedirectUriIsTooLong = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "\"redirect_uri\" is too long"));

    public static readonly TokenRequestAuthorizationCodeParameterRedirectUriValidationResult InvalidRedirectUri = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "Invalid \"redirect_uri\""));

    public TokenRequestAuthorizationCodeParameterRedirectUriValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public TokenRequestAuthorizationCodeParameterRedirectUriValidationResult(string? authorizeRequestRedirectUri)
    {
        AuthorizeRequestRedirectUri = authorizeRequestRedirectUri;
        HasError = false;
    }

    public string? AuthorizeRequestRedirectUri { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
