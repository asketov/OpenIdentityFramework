using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation.OpenIdConnect;

public class AuthorizeRequestOidcParameterNonceValidationResult
{
    public static readonly AuthorizeRequestOidcParameterNonceValidationResult Null = new((string?) null);

    public static readonly AuthorizeRequestOidcParameterNonceValidationResult NonceIsMissing = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "\"nonce\" is missing"));

    public static readonly AuthorizeRequestOidcParameterNonceValidationResult MultipleNonce = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Multiple \"nonce\" values are present, but only 1 has allowed"));

    public static readonly AuthorizeRequestOidcParameterNonceValidationResult NonceIsTooLong = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "\"nonce\" parameter is too long"));

    public AuthorizeRequestOidcParameterNonceValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestOidcParameterNonceValidationResult(string? nonce)
    {
        Nonce = nonce;
    }

    public string? Nonce { get; }
    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
