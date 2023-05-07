using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterCodeChallengeMethodValidationResult
{
    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult CodeChallengeMethodIsMissing = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "\"code_challenge_method\" is missing"));

    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult MultipleCodeChallengeMethod = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Multiple \"code_challenge_method\" values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult UnknownCodeChallengeMethod = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Unknown \"code_challenge_method\""));

    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult Plain = new(DefaultCodeChallengeMethod.Plain);

    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult S256 = new(DefaultCodeChallengeMethod.S256);

    public AuthorizeRequestParameterCodeChallengeMethodValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestParameterCodeChallengeMethodValidationResult(string codeChallengeMethod)
    {
        CodeChallengeMethod = codeChallengeMethod;
    }

    public string? CodeChallengeMethod { get; }
    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(CodeChallengeMethod))]
    public bool HasError { get; }
}
