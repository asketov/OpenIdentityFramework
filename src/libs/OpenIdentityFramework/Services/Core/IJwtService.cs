﻿using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Core;

public interface IJwtService<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<string> CreateIdTokenAsync(
        TRequestContext requestContext,
        SigningCredentials signingCredentials,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlySet<LightweightClaim> claims,
        CancellationToken cancellationToken);

    Task<string> CreateAccessTokenAsync(
        TRequestContext requestContext,
        SigningCredentials signingCredentials,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlySet<LightweightClaim> claims,
        CancellationToken cancellationToken);
}
