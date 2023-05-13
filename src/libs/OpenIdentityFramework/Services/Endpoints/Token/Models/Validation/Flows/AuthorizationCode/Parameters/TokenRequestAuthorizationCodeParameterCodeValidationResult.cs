using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode.Parameters;

public class TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public static readonly TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> AuthorizationCodeIsMissing = new(new(
        TokenErrors.InvalidRequest,
        "\"code\" is missing"));

    public static readonly TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> MultipleAuthorizationCodeValuesNotAllowed = new(new(
        TokenErrors.InvalidRequest,
        "Multiple \"code\" values are present, but only 1 has allowed"));

    public static readonly TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> AuthorizationCodeIsTooLong = new(new(
        TokenErrors.InvalidRequest,
        "\"code\" is too long"));

    public static readonly TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> InvalidAuthorizationCodeSyntax = new(new(
        TokenErrors.InvalidRequest,
        "Invalid \"code\" syntax"));

    public static readonly TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> UnknownCode = new(new(
        TokenErrors.InvalidGrant,
        "Unknown \"code\""));

    public TokenRequestAuthorizationCodeParameterCodeValidationResult(ProtocolError error)
    {
        Error = error;
        HasError = true;
    }

    public TokenRequestAuthorizationCodeParameterCodeValidationResult(string handle, TAuthorizationCode authorizationCode)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(authorizationCode);
        Handle = handle;
        AuthorizationCode = authorizationCode;
        HasError = false;
    }

    public string? Handle { get; }
    public TAuthorizationCode? AuthorizationCode { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(Handle))]
    [MemberNotNullWhen(false, nameof(AuthorizationCode))]
    public bool HasError { get; }
}
