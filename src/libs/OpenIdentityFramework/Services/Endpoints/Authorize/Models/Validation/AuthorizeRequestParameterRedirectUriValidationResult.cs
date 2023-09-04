using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterRedirectUriValidationResult
{
    public static readonly AuthorizeRequestParameterRedirectUriValidationResult RedirectUriIsMissing = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "\"redirect_uri\" is missing"));

    public static readonly AuthorizeRequestParameterRedirectUriValidationResult MultipleRedirectUriValuesNotAllowed = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Multiple \"redirect_uri\" values are present, but only one is allowed"));

    public static readonly AuthorizeRequestParameterRedirectUriValidationResult RedirectUriIsTooLong = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "\"redirect_uri\" is too long"));

    public static readonly AuthorizeRequestParameterRedirectUriValidationResult InvalidRedirectUriSyntax = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Invalid \"redirect_uri\" syntax"));

    public static readonly AuthorizeRequestParameterRedirectUriValidationResult InvalidRedirectUri = new(new ProtocolError(
        AuthorizeErrors.InvalidRequest,
        "Invalid \"redirect_uri\""));

    public static readonly AuthorizeRequestParameterRedirectUriValidationResult NoPreRegisteredRedirectUrisInClientConfiguration = new(new ProtocolError(
        AuthorizeErrors.ServerError,
        "The client configuration does not contain any pre-registered \"redirect_uri\""));

    public AuthorizeRequestParameterRedirectUriValidationResult(string redirectUri)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        RedirectUri = redirectUri;
    }

    public AuthorizeRequestParameterRedirectUriValidationResult(ProtocolError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        Error = error;
        HasError = true;
    }

    public string? RedirectUri { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(RedirectUri))]
    public bool HasError { get; }
}
