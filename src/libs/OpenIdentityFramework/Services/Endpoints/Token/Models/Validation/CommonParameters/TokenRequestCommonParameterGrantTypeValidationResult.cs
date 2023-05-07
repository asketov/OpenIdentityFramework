using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.CommonParameters;

public class TokenRequestCommonParameterGrantTypeValidationResult
{
    public static readonly TokenRequestCommonParameterGrantTypeValidationResult GrantTypeIsMissing = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "\"grant_type\" is missing"));

    public static readonly TokenRequestCommonParameterGrantTypeValidationResult MultipleGrantTypeValuesNotAllowed = new(new ProtocolError(
        TokenErrors.InvalidRequest,
        "Multiple \"grant_type\" values are present, but only 1 has allowed"));

    public static readonly TokenRequestCommonParameterGrantTypeValidationResult UnsupportedGrant = new(new ProtocolError(
        TokenErrors.UnsupportedGrantType,
        "Unsupported \"grant_type\""));

    public static readonly TokenRequestCommonParameterGrantTypeValidationResult AuthorizationCode = new(DefaultGrantTypes.AuthorizationCode);
    public static readonly TokenRequestCommonParameterGrantTypeValidationResult ClientCredentials = new(DefaultGrantTypes.ClientCredentials);
    public static readonly TokenRequestCommonParameterGrantTypeValidationResult RefreshToken = new(DefaultGrantTypes.RefreshToken);

    public TokenRequestCommonParameterGrantTypeValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public TokenRequestCommonParameterGrantTypeValidationResult(string grantType)
    {
        GrantType = grantType;
        HasError = false;
    }

    public string? GrantType { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(GrantType))]
    public bool HasError { get; }
}
