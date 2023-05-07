using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode.Parameters;

public class TokenRequestAuthorizationCodeParameterCodeVerifierValidationResult
{
    public static readonly TokenRequestAuthorizationCodeParameterCodeVerifierValidationResult CodeVerifierIsMissing = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "\"code_verifier\" is missing"));

    public static readonly TokenRequestAuthorizationCodeParameterCodeVerifierValidationResult MultipleCodeVerifierValuesNotAllowed = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "Multiple \"code_verifier\" values are present, but only 1 has allowed"));

    public static readonly TokenRequestAuthorizationCodeParameterCodeVerifierValidationResult CodeVerifierIsTooShort = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "\"code_verifier\" parameter is too short"));

    public static readonly TokenRequestAuthorizationCodeParameterCodeVerifierValidationResult CodeVerifierIsTooLong = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "\"code_verifier\" parameter is too long"));

    public static readonly TokenRequestAuthorizationCodeParameterCodeVerifierValidationResult InvalidCodeVerifierSyntax = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "Invalid \"code_verifier\" syntax"));

    public static readonly TokenRequestAuthorizationCodeParameterCodeVerifierValidationResult InvalidCodeVerifier = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "Invalid \"code_verifier\""));

    public TokenRequestAuthorizationCodeParameterCodeVerifierValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public TokenRequestAuthorizationCodeParameterCodeVerifierValidationResult(string codeVerifier)
    {
        CodeVerifier = codeVerifier;
        HasError = false;
    }

    public string? CodeVerifier { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(CodeVerifier))]
    public bool HasError { get; }
}
