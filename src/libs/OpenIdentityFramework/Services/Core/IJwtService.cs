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
        string issuer,
        IReadOnlySet<string> audiences,
        DateTimeOffset createdAt,
        TimeSpan lifetime,
        IReadOnlySet<LightweightClaim> claims,
        CancellationToken cancellationToken);
}
