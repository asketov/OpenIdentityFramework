using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;

public class ResourceOwnerProfile
{
    public ResourceOwnerProfile(EssentialResourceOwnerClaims essentialClaims, IReadOnlySet<LightweightClaim> profileClaims)
    {
        ArgumentNullException.ThrowIfNull(essentialClaims);
        ArgumentNullException.ThrowIfNull(profileClaims);
        EssentialClaims = essentialClaims;
        ProfileClaims = profileClaims;
    }

    public EssentialResourceOwnerClaims EssentialClaims { get; }
    public IReadOnlySet<LightweightClaim> ProfileClaims { get; }
}
