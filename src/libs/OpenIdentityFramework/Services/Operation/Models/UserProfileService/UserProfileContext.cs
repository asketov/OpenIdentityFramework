using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Operation.Models.UserProfileService;

[SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class UserProfileContext<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public UserProfileContext(TResourceOwnerIdentifiers resourceOwnerIdentifiers, IReadOnlySet<string> requestedClaimTypes)
    {
        ArgumentNullException.ThrowIfNull(resourceOwnerIdentifiers);
        ArgumentNullException.ThrowIfNull(requestedClaimTypes);
        ResourceOwnerIdentifiers = resourceOwnerIdentifiers;
        RequestedClaimTypes = requestedClaimTypes;
        Claims = null;
        IsActive = false;
    }

    public TResourceOwnerIdentifiers ResourceOwnerIdentifiers { get; protected set; }
    public IReadOnlySet<string> RequestedClaimTypes { get; protected set; }

    [MemberNotNullWhen(true, nameof(Claims))]
    public bool IsActive { get; protected set; }

    public IReadOnlySet<LightweightClaim>? Claims { get; protected set; }

    public void Active(IEnumerable<LightweightClaim>? claims)
    {
        var result = new HashSet<LightweightClaim>(LightweightClaim.EqualityComparer);
        if (claims != null)
        {
            foreach (var claim in claims)
            {
                if (RequestedClaimTypes.Contains(claim.Type))
                {
                    result.Add(claim);
                }
            }
        }

        Claims = result;
        IsActive = true;
    }

    public void Disabled()
    {
        Claims = null;
        IsActive = false;
    }
}
