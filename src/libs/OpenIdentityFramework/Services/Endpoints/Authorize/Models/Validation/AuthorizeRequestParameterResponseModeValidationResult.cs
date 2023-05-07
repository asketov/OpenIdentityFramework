using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterResponseModeValidationResult
{
    public static readonly AuthorizeRequestParameterResponseModeValidationResult Query = new(DefaultResponseMode.Query);
    public static readonly AuthorizeRequestParameterResponseModeValidationResult Fragment = new(DefaultResponseMode.Fragment);
    public static readonly AuthorizeRequestParameterResponseModeValidationResult FormPost = new(DefaultResponseMode.FormPost);

    public static readonly AuthorizeRequestParameterResponseModeValidationResult MultipleResponseModeValuesNotAllowed = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Multiple \"response_mode\" values are present, but only one is allowed"));

    public static readonly AuthorizeRequestParameterResponseModeValidationResult UnsupportedResponseMode = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Unsupported \"response_mode\""));

    public static readonly AuthorizeRequestParameterResponseModeValidationResult UnableToInferResponseMode = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
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
