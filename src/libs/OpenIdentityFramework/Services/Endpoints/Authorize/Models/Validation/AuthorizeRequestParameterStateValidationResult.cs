using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterStateValidationResult
{
    public static readonly AuthorizeRequestParameterStateValidationResult Null = new((string?) null);

    public static readonly AuthorizeRequestParameterStateValidationResult MultipleStateValuesNotAllowed = new(new ProtocolError(
        Errors.InvalidRequest,
        "Multiple \"state\" values are present, but only one is allowed"));

    public static readonly AuthorizeRequestParameterStateValidationResult StateIsTooLong = new(new ProtocolError(
        Errors.InvalidRequest,
        "\"state\" is too long"));

    public static readonly AuthorizeRequestParameterStateValidationResult InvalidStateSyntax = new(new ProtocolError(
        Errors.InvalidRequest,
        "Invalid \"state\" syntax"));

    public AuthorizeRequestParameterStateValidationResult(string? state)
    {
        State = state;
    }

    public AuthorizeRequestParameterStateValidationResult(ProtocolError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        Error = error;
        HasError = true;
    }

    public string? State { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
