using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterResponseTypeValidationResult
{
    public static readonly AuthorizeRequestParameterResponseTypeValidationResult Code = new(
        DefaultGrantTypes.AuthorizationCode,
        DefaultResponseTypes.Code);

    public static readonly AuthorizeRequestParameterResponseTypeValidationResult CodeIdToken = new(
        DefaultGrantTypes.AuthorizationCode,
        DefaultResponseTypes.CodeIdToken);

    public static readonly AuthorizeRequestParameterResponseTypeValidationResult ResponseTypeIsMissing = new(new(
        AuthorizeErrors.InvalidRequest,
        "\"response_type\" is missing"));

    public static readonly AuthorizeRequestParameterResponseTypeValidationResult MultipleResponseTypeValuesNotAllowed = new(new(
        AuthorizeErrors.InvalidRequest,
        "Multiple \"response_type\" values are present, but only one is allowed"));

    public static readonly AuthorizeRequestParameterResponseTypeValidationResult UnsupportedResponseType = new(new(
        AuthorizeErrors.UnsupportedResponseType,
        "Unsupported \"response_type\""));

    public AuthorizeRequestParameterResponseTypeValidationResult(ProtocolError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestParameterResponseTypeValidationResult(string grantType, IReadOnlySet<string> responseType)
    {
        ArgumentNullException.ThrowIfNull(grantType);
        ArgumentNullException.ThrowIfNull(responseType);
        GrantType = grantType;
        ResponseType = responseType;
    }

    public string? GrantType { get; }
    public IReadOnlySet<string>? ResponseType { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(ResponseType))]
    [MemberNotNullWhen(false, nameof(GrantType))]
    public bool HasError { get; }
}
