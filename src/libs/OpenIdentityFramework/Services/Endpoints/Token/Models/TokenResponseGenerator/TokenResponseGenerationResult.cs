using System;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.TokenResponseGenerator;

public class TokenResponseGenerationResult
{
    public TokenResponseGenerationResult(SuccessfulTokenResponse tokenResponse)
    {
        ArgumentNullException.ThrowIfNull(tokenResponse);
        TokenResponse = tokenResponse;
    }

    public TokenResponseGenerationResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        ErrorDescription = errorDescription;
        HasError = true;
    }

    public SuccessfulTokenResponse? TokenResponse { get; }
    public string? ErrorDescription { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    [MemberNotNullWhen(false, nameof(TokenResponse))]
    public bool HasError { get; }
}
