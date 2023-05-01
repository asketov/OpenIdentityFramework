using System;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

public class AuthorizeResponseGenerationResult
{
    public AuthorizeResponseGenerationResult(SuccessfulAuthorizeResponse authorizeResponse)
    {
        ArgumentNullException.ThrowIfNull(authorizeResponse);
        AuthorizeResponse = authorizeResponse;
    }

    public AuthorizeResponseGenerationResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        ErrorDescription = errorDescription;
        HasError = true;
    }

    public SuccessfulAuthorizeResponse? AuthorizeResponse { get; }
    public string? ErrorDescription { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    [MemberNotNullWhen(false, nameof(AuthorizeResponse))]
    public bool HasError { get; }
}
