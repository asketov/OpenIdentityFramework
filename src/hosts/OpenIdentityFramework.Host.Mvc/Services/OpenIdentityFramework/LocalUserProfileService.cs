using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Host.Mvc.Services.Local;
using OpenIdentityFramework.Host.Mvc.Services.Local.Models;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Services.Operation.Models.UserProfileService;

namespace OpenIdentityFramework.Host.Mvc.Services.OpenIdentityFramework;

public class LocalUserProfileService<TRequestContext, TResourceOwnerIdentifiers> : IUserProfileService<TRequestContext, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    private readonly ILocalUserService _users;

    public LocalUserProfileService(ILocalUserService users)
    {
        ArgumentNullException.ThrowIfNull(users);
        _users = users;
    }

    public async Task GetProfileAsync(TRequestContext requestContext, UserProfileContext<TResourceOwnerIdentifiers> resultContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(resultContext);
        var userId = new Guid(resultContext.ResourceOwnerIdentifiers.GetSubjectId());
        var user = await _users.FindByIdAsync(userId, cancellationToken);
        if (user is not null)
        {
            var claims = ToOpenIdClaims(user);
            resultContext.Active(claims);
        }
        else
        {
            resultContext.Disabled();
        }
    }

    public async Task<bool> IsActiveAsync(TRequestContext requestContext, TResourceOwnerIdentifiers resourceOwnerIdentifiers, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resourceOwnerIdentifiers);
        var userId = new Guid(resourceOwnerIdentifiers.GetSubjectId());
        return await _users.IsActiveAsync(userId, cancellationToken);
    }

    private static HashSet<LightweightClaim> ToOpenIdClaims(LocalUser user)
    {
        var result = new HashSet<LightweightClaim>(LightweightClaim.EqualityComparer)
        {
            new(DefaultJwtClaimTypes.Subject, user.Id.ToString("N")),
            new(JwtRegisteredClaimNames.Name, user.Login)
        };
        foreach (var userRole in user.Roles ?? Enumerable.Empty<string>())
        {
            result.Add(new("role", userRole));
        }

        return result;
    }
}
