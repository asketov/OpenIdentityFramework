using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

public class AuthorizeRequestOidcParameterRegistrationValidationResult
{
    public static readonly AuthorizeRequestOidcParameterRegistrationValidationResult Null = new();

    public static readonly AuthorizeRequestOidcParameterRegistrationValidationResult MultipleRegistrationValues = new(new(
        Errors.InvalidRequest,
        "Multiple \"registration\" parameter values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestOidcParameterRegistrationValidationResult RegistrationNotSupported = new(new(
        Errors.RegistrationNotSupported,
        "\"registration\" parameter provided but not supported"));

    public AuthorizeRequestOidcParameterRegistrationValidationResult()
    {
    }

    public AuthorizeRequestOidcParameterRegistrationValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
