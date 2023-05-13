using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Operation.Models.ResourceOwnerEssentialClaimsFactory;

public class ResourceOwnerEssentialClaimsCreationResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public ResourceOwnerEssentialClaimsCreationResult(TResourceOwnerEssentialClaims essentialClaims)
    {
        ArgumentNullException.ThrowIfNull(essentialClaims);
        EssentialClaims = essentialClaims;
    }

    public ResourceOwnerEssentialClaimsCreationResult(string errorDescription)
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
