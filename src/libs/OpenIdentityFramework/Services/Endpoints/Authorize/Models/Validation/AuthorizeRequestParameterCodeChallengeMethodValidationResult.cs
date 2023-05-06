using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterCodeChallengeMethodValidationResult
{
    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult CodeChallengeMethodIsMissing = new(new ProtocolError(
        Errors.InvalidRequest,
        "\"code_challenge_method\" is missing"));

    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult MultipleCodeChallengeMethod = new(new ProtocolError(
        Errors.InvalidRequest,
        "Multiple \"code_challenge_method\" values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult UnknownCodeChallengeMethod = new(new ProtocolError(
        Errors.InvalidRequest,
        "Unknown \"code_challenge_method\""));

    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult Plain = new(Constants.Request.Authorize.CodeChallengeMethod.Plain);

    public static readonly AuthorizeRequestParameterCodeChallengeMethodValidationResult S256 = new(Constants.Request.Authorize.CodeChallengeMethod.S256);

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
