using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.RefreshToken.Parameters;

public class TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public static readonly TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> RefreshTokenIsMissing = new(new(
        TokenErrors.InvalidRequest,
        "\"refresh_token\" is missing"));

    public static readonly TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> MultipleRefreshTokenValuesNotAllowed = new(new(
        TokenErrors.InvalidRequest,
        "Multiple \"refresh_token\" values are present, but only 1 has allowed"));

    public static readonly TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> RefreshTokenIsTooLong = new(new(
        TokenErrors.InvalidRequest,
        "\"refresh_token\" is too long"));

    public static readonly TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> UnknownRefreshToken = new(new(
        TokenErrors.InvalidGrant,
        "Unknown \"refresh_token\""));

    public static readonly TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> InactiveUser = new(new(
        TokenErrors.InvalidGrant,
        "User account for provided \"refresh_token\" has been disabled"));

    public TokenRequestRefreshTokenParameterRefreshTokenValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public TokenRequestRefreshTokenParameterRefreshTokenValidationResult(string handle, TRefreshToken refreshToken)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(refreshToken);
        Handle = handle;
        RefreshToken = refreshToken;
        HasError = false;
    }

    public string? Handle { get; }
    public TRefreshToken? RefreshToken { get; }
    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(Handle))]
    [MemberNotNullWhen(false, nameof(RefreshToken))]
    public bool HasError { get; }
}
