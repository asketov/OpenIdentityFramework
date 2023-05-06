using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

public class AuthorizeRequestOidcParameterRequestUriValidationResult
{
    public static readonly AuthorizeRequestOidcParameterRequestUriValidationResult Null = new();

    public static readonly AuthorizeRequestOidcParameterRequestUriValidationResult MultipleRequestUriValues = new(new(
        Errors.InvalidRequest,
        "Multiple \"request_uri\" parameter values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestOidcParameterRequestUriValidationResult RequestUriNotSupported = new(new(
        Errors.RequestUriNotSupported,
        "\"request_uri\" parameter provided but not supported"));

    public AuthorizeRequestOidcParameterRequestUriValidationResult()
    {
    }

    public AuthorizeRequestOidcParameterRequestUriValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
