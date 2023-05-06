using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterCodeChallengeValidationResult
{
    public static readonly AuthorizeRequestParameterCodeChallengeValidationResult CodeChallengeIsMissing = new(new ProtocolError(
        Errors.InvalidRequest,
        "\"code_challenge\" is missing"));

    public static readonly AuthorizeRequestParameterCodeChallengeValidationResult MultipleCodeChallenge = new(new ProtocolError(
        Errors.InvalidRequest,
        "Multiple \"code_challenge\" values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestParameterCodeChallengeValidationResult CodeChallengeIsTooShort = new(new ProtocolError(
        Errors.InvalidRequest,
        "\"code_challenge\" parameter is too short"));

    public static readonly AuthorizeRequestParameterCodeChallengeValidationResult CodeChallengeIsTooLong = new(new ProtocolError(
        Errors.InvalidRequest,
        "\"code_challenge\" parameter is too long"));

    public static readonly AuthorizeRequestParameterCodeChallengeValidationResult InvalidCodeChallengeSyntax = new(new ProtocolError(
        Errors.InvalidRequest,
        "Invalid \"code_challenge\" syntax"));

    public AuthorizeRequestParameterCodeChallengeValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestParameterCodeChallengeValidationResult(string codeChallenge)
    {
        CodeChallenge = codeChallenge;
    }

    public string? CodeChallenge { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(CodeChallenge))]
    public bool HasError { get; }
}
