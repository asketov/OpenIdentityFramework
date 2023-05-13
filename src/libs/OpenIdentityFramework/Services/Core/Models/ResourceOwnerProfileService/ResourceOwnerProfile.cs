using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;

public class ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public ResourceOwnerProfile(TResourceOwnerEssentialClaims essentialClaims, IReadOnlySet<LightweightClaim> profileClaims)
    {
        ArgumentNullException.ThrowIfNull(essentialClaims);
        ArgumentNullException.ThrowIfNull(profileClaims);
        EssentialClaims = essentialClaims;
        ProfileClaims = profileClaims;
    }

    public TResourceOwnerEssentialClaims EssentialClaims { get; }
    public IReadOnlySet<LightweightClaim> ProfileClaims { get; }
}
