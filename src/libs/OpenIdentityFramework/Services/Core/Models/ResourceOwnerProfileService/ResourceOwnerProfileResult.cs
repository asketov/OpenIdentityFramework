using System;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;

public class ResourceOwnerProfileResult
{
    public ResourceOwnerProfileResult(ResourceOwnerProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        Profile = profile;
        IsActive = true;
    }

    public ResourceOwnerProfileResult()
    {
        IsActive = false;
    }

    public ResourceOwnerProfile? Profile { get; }

    [MemberNotNullWhen(true, nameof(Profile))]
    public bool IsActive { get; }
}
