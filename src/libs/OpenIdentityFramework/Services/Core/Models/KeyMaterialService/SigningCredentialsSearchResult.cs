using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.IdentityModel.Tokens;

namespace OpenIdentityFramework.Services.Core.Models.KeyMaterialService;

public class SigningCredentialsSearchResult
{
    public SigningCredentialsSearchResult(SigningCredentials signingCredentials)
    {
        ArgumentNullException.ThrowIfNull(signingCredentials);
        SigningCredentials = signingCredentials;
    }

    public SigningCredentialsSearchResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        ErrorDescription = errorDescription;
        HasError = true;
    }

    public SigningCredentials? SigningCredentials { get; }

    public string? ErrorDescription { get; }

    [MemberNotNullWhen(false, nameof(SigningCredentials))]
    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    public bool HasError { get; }
}
