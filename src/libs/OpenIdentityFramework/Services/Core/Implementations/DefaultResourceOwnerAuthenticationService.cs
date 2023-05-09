using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultResourceOwnerAuthenticationService<TRequestContext>
    : IResourceOwnerAuthenticationService<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    public DefaultResourceOwnerAuthenticationService(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthenticationSchemeProvider schemeProvider)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(schemeProvider);
        FrameworkOptions = frameworkOptions;
        SchemeProvider = schemeProvider;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IAuthenticationSchemeProvider SchemeProvider { get; }

    public virtual async Task<ResourceOwnerAuthenticationResult> AuthenticateAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        string runtimeScheme;
        if (FrameworkOptions.Authentication.AuthenticationScheme != null)
        {
            runtimeScheme = FrameworkOptions.Authentication.AuthenticationScheme;
        }
        else
        {
            var defaultAuthenticationScheme = await SchemeProvider.GetDefaultAuthenticateSchemeAsync();
            if (defaultAuthenticationScheme == null)
            {
                return new("Default authentication scheme not found");
            }

            runtimeScheme = defaultAuthenticationScheme.Name;
        }

        var authenticationResult = await requestContext.HttpContext.AuthenticateAsync(runtimeScheme);
        return await HandleAuthenticateResultAsync(requestContext, authenticationResult, cancellationToken);
    }

    protected virtual Task<ResourceOwnerAuthenticationResult> HandleAuthenticateResultAsync(
        TRequestContext requestContext,
        AuthenticateResult? authenticateResult,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (authenticateResult is null || !authenticateResult.Succeeded || authenticateResult.Ticket.Principal.Identity?.IsAuthenticated != true)
        {
            return Task.FromResult(new ResourceOwnerAuthenticationResult());
        }

        if (!TryGetSingleClaimValue(authenticateResult.Ticket.Principal, FrameworkOptions.Authentication.SubjectIdClaimType, out var subjectId))
        {
            return Task.FromResult(new ResourceOwnerAuthenticationResult($"Can't read \"{FrameworkOptions.Authentication.SubjectIdClaimType}\" claim"));
        }

        if (!TryGetSingleClaimValue(authenticateResult.Ticket.Principal, FrameworkOptions.Authentication.SessionIdClaimType, out var sessionId))
        {
            return Task.FromResult(new ResourceOwnerAuthenticationResult($"Can't read \"{FrameworkOptions.Authentication.SessionIdClaimType}\" claim"));
        }

        if (!TryGetAuthenticationDate(authenticateResult.Ticket, out var authenticatedAt))
        {
            return Task.FromResult(new ResourceOwnerAuthenticationResult($"Can't read \"{typeof(AuthenticationTicket).Namespace}.{nameof(AuthenticationTicket)}.{nameof(AuthenticationTicket.Properties)}.{nameof(AuthenticationProperties.IssuedUtc)}\" authentication property"));
        }

        var identifiers = new ResourceOwnerIdentifiers(subjectId, sessionId);
        var essentialClaims = new EssentialResourceOwnerClaims(identifiers, authenticatedAt.Value);
        var authentication = new ResourceOwnerAuthentication(essentialClaims, authenticateResult.Ticket);
        return Task.FromResult(new ResourceOwnerAuthenticationResult(authentication));
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
