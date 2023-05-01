using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Core;

public interface IJwtService
{
    Task<string> CreateIdTokenAsync(
        HttpContext httpContext,
        SigningCredentials signingCredentials,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlySet<LightweightClaim> claims,
        CancellationToken cancellationToken);

    Task<string> CreateAccessTokenAsync(
        HttpContext httpContext,
        SigningCredentials signingCredentials,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlySet<LightweightClaim> claims,
        CancellationToken cancellationToken);
}
