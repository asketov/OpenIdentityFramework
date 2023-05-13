using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;

public class ResourceOwnerProfileResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public ResourceOwnerProfileResult(ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        Profile = profile;
        IsActive = true;
    }

    public ResourceOwnerProfileResult()
    {
        IsActive = false;
    }

    public ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? Profile { get; }

    [MemberNotNullWhen(true, nameof(Profile))]
    public bool IsActive { get; }
}
