using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterResponseTypeValidationResult
{
    public static readonly AuthorizeRequestParameterResponseTypeValidationResult Code = new(
        Constants.Request.Authorize.ResponseType.Code,
        DefaultAuthorizationFlows.AuthorizationCode);

    public static readonly AuthorizeRequestParameterResponseTypeValidationResult CodeIdToken = new(
        Constants.Request.Authorize.ResponseType.CodeIdToken,
        DefaultAuthorizationFlows.Hybrid);

    public static readonly AuthorizeRequestParameterResponseTypeValidationResult ResponseTypeIsMissing = new(new(
        Errors.InvalidRequest,
        "\"response_type\" is missing"));

    public static readonly AuthorizeRequestParameterResponseTypeValidationResult MultipleResponseTypeValuesNotAllowed = new(new(
        Errors.InvalidRequest,
        "Multiple \"response_type\" values are present, but only one is allowed"));

    public static readonly AuthorizeRequestParameterResponseTypeValidationResult UnsupportedResponseType = new(new(
        Errors.UnsupportedResponseType,
        "Unsupported \"response_type\""));

    public AuthorizeRequestParameterResponseTypeValidationResult(ProtocolError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestParameterResponseTypeValidationResult(string responseType, string authorizationFlow)
    {
        ArgumentNullException.ThrowIfNull(responseType);
        ArgumentNullException.ThrowIfNull(authorizationFlow);
        ResponseType = responseType;
        AuthorizationFlow = authorizationFlow;
    }

    public string? ResponseType { get; }

    public string? AuthorizationFlow { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(ResponseType))]
    [MemberNotNullWhen(false, nameof(AuthorizationFlow))]
    public bool HasError { get; }
}
