using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Operation.Models.ResourceOwnerEssentialClaimsProvider;

public class ResourceOwnerEssentialClaimsResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public ResourceOwnerEssentialClaimsResult(TResourceOwnerEssentialClaims essentialClaims)
    {
        ArgumentNullException.ThrowIfNull(essentialClaims);
        EssentialClaims = essentialClaims;
    }

    public ResourceOwnerEssentialClaimsResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        ErrorDescription = errorDescription;
        HasError = true;
    }

    public TResourceOwnerEssentialClaims? EssentialClaims { get; }

    public string? ErrorDescription { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    [MemberNotNullWhen(false, nameof(EssentialClaims))]
    public bool HasError { get; }
}
