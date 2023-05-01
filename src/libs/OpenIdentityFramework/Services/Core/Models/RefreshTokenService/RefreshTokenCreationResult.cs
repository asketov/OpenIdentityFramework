using System;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Services.Core.Models.RefreshTokenService;

public class RefreshTokenCreationResult
{
    public RefreshTokenCreationResult(CreatedRefreshToken refreshToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        RefreshToken = refreshToken;
    }

    public RefreshTokenCreationResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        ErrorDescription = errorDescription;
        HasError = true;
    }

    public CreatedRefreshToken? RefreshToken { get; }

    public string? ErrorDescription { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    [MemberNotNullWhen(false, nameof(RefreshToken))]
    public bool HasError { get; }
}
