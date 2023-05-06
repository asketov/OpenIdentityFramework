using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterResponseModeValidationResult
{
    public static readonly AuthorizeRequestParameterResponseModeValidationResult Query = new(Constants.Request.Authorize.ResponseMode.Query);
    public static readonly AuthorizeRequestParameterResponseModeValidationResult Fragment = new(Constants.Request.Authorize.ResponseMode.Fragment);
    public static readonly AuthorizeRequestParameterResponseModeValidationResult FormPost = new(Constants.Request.Authorize.ResponseMode.FormPost);

    public static readonly AuthorizeRequestParameterResponseModeValidationResult MultipleResponseModeValuesNotAllowed = new(new ProtocolError(
        Errors.InvalidRequest,
        "Multiple \"response_mode\" values are present, but only one is allowed"));

    public static readonly AuthorizeRequestParameterResponseModeValidationResult UnsupportedResponseMode = new(new ProtocolError(
        Errors.InvalidRequest,
        "Unsupported \"response_mode\""));

    public static readonly AuthorizeRequestParameterResponseModeValidationResult UnableToInferResponseMode = new(new ProtocolError(
        Errors.InvalidRequest,
        "Unable to infer parameter \"response_mode\""));

    public AuthorizeRequestParameterResponseModeValidationResult(string responseMode)
    {
        ArgumentNullException.ThrowIfNull(responseMode);
        ResponseMode = responseMode;
    }

    public AuthorizeRequestParameterResponseModeValidationResult(ProtocolError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        Error = error;
        HasError = true;
    }

    public string? ResponseMode { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(ResponseMode))]
    public bool HasError { get; }
}
