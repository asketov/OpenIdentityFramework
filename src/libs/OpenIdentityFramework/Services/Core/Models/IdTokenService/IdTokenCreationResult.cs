using System;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Services.Core.Models.IdTokenService;

public class IdTokenCreationResult
{
    public IdTokenCreationResult(CreatedIdToken idToken)
    {
        ArgumentNullException.ThrowIfNull(idToken);
        IdToken = idToken;
    }

    public IdTokenCreationResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        ErrorDescription = errorDescription;
        HasError = true;
    }

    public CreatedIdToken? IdToken { get; }

    public string? ErrorDescription { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    [MemberNotNullWhen(false, nameof(IdToken))]
    public bool HasError { get; }
}
