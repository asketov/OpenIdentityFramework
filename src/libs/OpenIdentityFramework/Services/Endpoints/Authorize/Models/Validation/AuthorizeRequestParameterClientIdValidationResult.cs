using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants.Response.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public static readonly AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret> ClientIdIsMissing = new(new ProtocolError(
        Errors.InvalidRequest,
        "\"client_id\" is missing"));

    public static readonly AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret> MultipleClientIdValuesNotAllowed = new(new ProtocolError(
        Errors.InvalidRequest,
        "Multiple \"client_id\" values are present, but only one is allowed"));

    public static readonly AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret> ClientIdIsTooLong = new(new ProtocolError(
        Errors.InvalidRequest,
        "\"client_id\" is too long"));

    public static readonly AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret> InvalidClientIdSyntax = new(new ProtocolError(
        Errors.InvalidRequest,
        "Invalid \"client_id\" syntax"));

    public static readonly AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret> UnknownOrDisabledClient = new(new ProtocolError(
        Errors.UnauthorizedClient,
        "Unknown or disabled client"));

    public AuthorizeRequestParameterClientIdValidationResult(ProtocolError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        Error = error;
        HasError = true;
    }

    public AuthorizeRequestParameterClientIdValidationResult(TClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        Client = client;
    }

    public TClient? Client { get; }

    public ProtocolError? Error { get; }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(Client))]
    public bool HasError { get; }
}
