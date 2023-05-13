﻿using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Services.Operation.Models.ResourceOwnerEssentialClaimsFactory;

namespace OpenIdentityFramework.Services.Operation;

public interface IResourceOwnerEssentialClaimsFactory<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<ResourceOwnerEssentialClaimsCreationResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> CreateAsync(
        TRequestContext requestContext,
        AuthenticationTicket authenticationTicket,
        CancellationToken cancellationToken);
}
