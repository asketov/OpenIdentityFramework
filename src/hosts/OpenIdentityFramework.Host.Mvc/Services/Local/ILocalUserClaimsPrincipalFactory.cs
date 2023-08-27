using System.Security.Claims;
using OpenIdentityFramework.Host.Mvc.Services.Local.Models;

namespace OpenIdentityFramework.Host.Mvc.Services.Local;

public interface ILocalUserClaimsPrincipalFactory
{
    ClaimsPrincipal CreateClaimsPrincipal(LocalUser localUser);
}
