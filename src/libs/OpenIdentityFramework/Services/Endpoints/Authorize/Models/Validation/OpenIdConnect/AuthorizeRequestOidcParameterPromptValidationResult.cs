using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

public class AuthorizeRequestOidcParameterPromptValidationResult
{
    public static readonly AuthorizeRequestOidcParameterPromptValidationResult Null = new((IReadOnlySet<string>?) null);

    public static readonly AuthorizeRequestOidcParameterPromptValidationResult MultiplePrompt = new(new ProtocolError(
        Errors.InvalidRequest,
        "Multiple \"prompt\" parameter values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestOidcParameterPromptValidationResult UnsupportedPrompt = new(new ProtocolError(
        Errors.InvalidRequest,
        "Provided \"prompt\" is not supported"));

    public AuthorizeRequestOidcParameterPromptValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestOidcParameterPromptValidationResult(IReadOnlySet<string>? prompt)
    {
        Prompt = prompt;
    }

    public IReadOnlySet<string>? Prompt { get; }
    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
