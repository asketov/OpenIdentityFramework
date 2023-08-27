using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Host.Mvc.Constants;
using OpenIdentityFramework.Host.Mvc.Services.Local.Models;

namespace OpenIdentityFramework.Host.Mvc.Services.Local.Implementations.ClaimsPrincipalFactory;

public class LocalUserClaimsPrincipalPrincipalFactory : ILocalUserClaimsPrincipalFactory
{
    private readonly LocalUserClaimsPrincipalPrincipalFactoryOptions _options;

    public LocalUserClaimsPrincipalPrincipalFactory(IOptions<LocalUserClaimsPrincipalPrincipalFactoryOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
    }

    public ClaimsPrincipal CreateClaimsPrincipal(LocalUser localUser)
    {
        var claims = CreateClaims(localUser).ToArray();
        var claimsIdentity = new ClaimsIdentity(claims, _options.AuthenticationType, _options.NameClaimType, _options.RoleClaimType);
        var principal = new ClaimsPrincipal(claimsIdentity);
        return principal;
    }

    private static IEnumerable<Claim> CreateClaims(LocalUser localUser)
    {
        ArgumentNullException.ThrowIfNull(localUser);
        yield return new(LocalUserClaimTypes.UserId, localUser.Id.ToString("N"), DefaultClaimValueTypes.String);
        yield return new(LocalUserClaimTypes.Login, localUser.Login, DefaultClaimValueTypes.String);
        foreach (var role in localUser.Roles ?? Enumerable.Empty<string>())
        {
            yield return new(LocalUserClaimTypes.Role, role, DefaultClaimValueTypes.String);
        }

        yield return new(LocalUserClaimTypes.SessionId, Guid.NewGuid().ToString("N"), DefaultClaimValueTypes.String);
    }
}
