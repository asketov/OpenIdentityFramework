using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Services.Operation.Models.ResourceOwnerEssentialClaimsFactory;

namespace OpenIdentityFramework.InMemory.Services.Operation.ResourceOwnerEssentialClaimsFactory;

public class InMemoryResourceOwnerEssentialClaimsProvider
    : IResourceOwnerEssentialClaimsProvider<InMemoryRequestContext, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>
{
    public InMemoryResourceOwnerEssentialClaimsProvider(IOptions<InMemoryResourceOwnerEssentialClaimsFactoryOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var optionsValue = options.Value;
        SubjectIdClaimType = optionsValue.SubjectIdClaimType;
        SessionIdIdClaimType = optionsValue.SessionIdIdClaimType;
    }

    protected string SubjectIdClaimType { get; }
    protected string SessionIdIdClaimType { get; }

    public virtual Task<ResourceOwnerEssentialClaimsCreationResult<InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>> GetAsync(
        InMemoryRequestContext requestContext,
        AuthenticationTicket authenticationTicket,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticationTicket);
        cancellationToken.ThrowIfCancellationRequested();
        if (!TryGetSingleClaimValue(authenticationTicket.Principal, SubjectIdClaimType, out var subjectId))
        {
            return Task.FromResult(new ResourceOwnerEssentialClaimsCreationResult<InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>(
                $"Can't read \"{SubjectIdClaimType}\" claim"));
        }

        if (!TryGetSingleClaimValue(authenticationTicket.Principal, SessionIdIdClaimType, out var sessionId))
        {
            return Task.FromResult(new ResourceOwnerEssentialClaimsCreationResult<InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>(
                $"Can't read \"{SessionIdIdClaimType}\" claim"));
        }

        if (!TryGetAuthenticationDate(authenticationTicket, out var authenticatedAt))
        {
            return Task.FromResult(new ResourceOwnerEssentialClaimsCreationResult<InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>(
                $"Can't read \"{typeof(AuthenticationTicket).Namespace}.{nameof(AuthenticationTicket)}.{nameof(AuthenticationTicket.Properties)}.{nameof(AuthenticationProperties.IssuedUtc)}\" authentication property"));
        }

        var identifiers = new InMemoryResourceOwnerIdentifiers(subjectId, sessionId);
        var essentialClaims = new InMemoryResourceOwnerEssentialClaims(identifiers, authenticatedAt.Value);
        var result = new ResourceOwnerEssentialClaimsCreationResult<InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>(essentialClaims);
        return Task.FromResult(result);
    }

    protected virtual bool TryGetSingleClaimValue(ClaimsPrincipal principal, string claimType, [NotNullWhen(true)] out string? value)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var claim = principal.Claims.SingleOrDefault(x => x.Type == claimType);
        if (claim is not null && !string.IsNullOrEmpty(claim.Value))
        {
            value = claim.Value;
            return true;
        }

        value = null;
        return false;
    }

    protected virtual bool TryGetAuthenticationDate(AuthenticationTicket? authenticationTicket, [NotNullWhen(true)] out DateTimeOffset? value)
    {
        var issuedAt = authenticationTicket?.Properties.IssuedUtc;
        if (issuedAt.HasValue)
        {
            value = issuedAt.Value;
            return true;
        }

        value = null;
        return false;
    }
}
