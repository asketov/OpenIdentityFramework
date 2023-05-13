using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Services.Operation.Models.UserProfileService;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    : IResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultResourceOwnerProfileService(IUserProfileService<TRequestContext, TResourceOwnerIdentifiers> userProfile)
    {
        ArgumentNullException.ThrowIfNull(userProfile);
        UserProfile = userProfile;
    }

    protected IUserProfileService<TRequestContext, TResourceOwnerIdentifiers> UserProfile { get; }

    public virtual async Task<ResourceOwnerProfileResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> GetResourceOwnerProfileAsync(
        TRequestContext requestContext,
        TResourceOwnerEssentialClaims essentialClaims,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(essentialClaims);
        cancellationToken.ThrowIfCancellationRequested();
        var profileClaimTypes = GetProfileClaimTypes(grantedResources);
        var profileContext = new UserProfileContext<TResourceOwnerIdentifiers>(essentialClaims.GetResourceOwnerIdentifiers(), profileClaimTypes);
        await UserProfile.GetProfileAsync(requestContext, profileContext, cancellationToken);
        if (!profileContext.IsActive)
        {
            return new();
        }

        var profile = new ResourceOwnerProfile<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>(essentialClaims, profileContext.Claims);
        return new(profile);
    }

    public virtual async Task<bool> IsActiveAsync(
        TRequestContext requestContext,
        TResourceOwnerIdentifiers resourceOwnerIdentifiers,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await UserProfile.IsActiveAsync(requestContext, resourceOwnerIdentifiers, cancellationToken);
    }

    protected virtual IReadOnlySet<string> GetProfileClaimTypes(ValidResources<TScope, TResource, TResourceSecret> grantedResources)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        var result = new HashSet<string>(256, StringComparer.Ordinal);
        foreach (var accessTokenScope in grantedResources.AccessTokenScopes)
        {
            foreach (var userClaimType in accessTokenScope.GetUserClaimTypes())
            {
                if (!DefaultJwtClaimTypes.Restrictions.Contains(userClaimType))
                {
                    result.Add(userClaimType);
                }
            }
        }

        foreach (var idTokenScope in grantedResources.IdTokenScopes)
        {
            foreach (var userClaimType in idTokenScope.GetUserClaimTypes())
            {
                if (!DefaultJwtClaimTypes.Restrictions.Contains(userClaimType))
                {
                    result.Add(userClaimType);
                }
            }
        }

        return result;
    }
}
