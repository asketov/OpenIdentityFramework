using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Core;

public interface IJwtService<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    Task<string> CreateIdTokenAsync(
        TRequestContext requestContext,
        SigningCredentials signingCredentials,
        IReadOnlySet<LightweightClaim> claims,
        CancellationToken cancellationToken);

    Task<string> CreateAccessTokenAsync(
        TRequestContext requestContext,
        SigningCredentials signingCredentials,
        IReadOnlySet<LightweightClaim> claims,
        CancellationToken cancellationToken);
}
