using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

public class AuthorizeRequestOidcParameterMaxAgeValidationResult
{
    public static readonly AuthorizeRequestOidcParameterMaxAgeValidationResult Null = new((long?) null);

    public static readonly AuthorizeRequestOidcParameterMaxAgeValidationResult MultipleMaxAge = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Multiple \"max_age\" parameter values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestOidcParameterMaxAgeValidationResult InvalidMaxAge = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Invalid \"max_age\" parameter value"));

    public AuthorizeRequestOidcParameterMaxAgeValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestOidcParameterMaxAgeValidationResult(long? maxAge)
    {
        MaxAge = maxAge;
    }

    public long? MaxAge { get; }
    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
