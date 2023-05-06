using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

public class AuthorizeRequestOidcParameterAcrValuesValidationResult
{
    public static readonly AuthorizeRequestOidcParameterAcrValuesValidationResult Null = new((string[]?) null);

    public static readonly AuthorizeRequestOidcParameterAcrValuesValidationResult MultipleAcrValuesValues = new(new ProtocolError(
        Errors.InvalidRequest,
        "Multiple \"acr_values\" parameter values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestOidcParameterAcrValuesValidationResult AcrValuesIsTooLong = new(new ProtocolError(
        Errors.InvalidRequest,
        "\"acr_values\" parameter is too long"));

    public static readonly AuthorizeRequestOidcParameterAcrValuesValidationResult InvalidAcrValuesSyntax = new(new ProtocolError(
        Errors.InvalidRequest,
        "Invalid \"acr_values\" syntax"));

    public AuthorizeRequestOidcParameterAcrValuesValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestOidcParameterAcrValuesValidationResult(string[]? acrValues)
    {
        AcrValues = acrValues;
    }

    public string[]? AcrValues { get; }
    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
