using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultUserAuthenticationTicketService : IUserAuthenticationTicketService
{
    public DefaultUserAuthenticationTicketService(OpenIdentityFrameworkOptions frameworkOptions, IAuthenticationSchemeProvider schemeProvider)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(schemeProvider);
        FrameworkOptions = frameworkOptions;
        SchemeProvider = schemeProvider;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IAuthenticationSchemeProvider SchemeProvider { get; }

    public virtual async Task<UserAuthenticationResult> AuthenticateAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
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

        var authenticationResult = await httpContext.AuthenticateAsync(runtimeScheme);
        return await HandleAuthenticateResultAsync(httpContext, authenticationResult, cancellationToken);
    }

    protected virtual async Task<UserAuthenticationResult> HandleAuthenticateResultAsync(
        HttpContext httpContext,
        AuthenticateResult? authenticateResult,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (authenticateResult is null || !authenticateResult.Succeeded || authenticateResult.Ticket.Principal.Identity?.IsAuthenticated != true)
        {
            return new();
        }

        if (!TryGetSingleClaimValue(authenticateResult.Ticket.Principal, FrameworkOptions.Authentication.SubjectIdClaimType, out var subjectId))
        {
            return new($"Can't read \"{FrameworkOptions.Authentication.SubjectIdClaimType}\" claim");
        }

        if (!TryGetSingleClaimValue(authenticateResult.Ticket.Principal, FrameworkOptions.Authentication.SessionIdClaimType, out var sessionId))
        {
            return new($"Can't read \"{FrameworkOptions.Authentication.SessionIdClaimType}\" claim");
        }

        if (!TryGetAuthenticationDate(authenticateResult.Ticket, out var authenticatedAt))
        {
            return new($"Can't read \"{typeof(AuthenticationTicket).Namespace}.{nameof(AuthenticationTicket)}.{nameof(AuthenticationTicket.Properties)}.{nameof(AuthenticationProperties.IssuedUtc)}\" authentication property");
        }

        var customClaims = await GetCustomClaimsAsync(httpContext, authenticateResult.Ticket, cancellationToken);
        var userAuthentication = new UserAuthentication(subjectId, sessionId, authenticatedAt.Value, customClaims);
        var resultTicket = new UserAuthenticationTicket(userAuthentication, authenticateResult.Ticket);
        return new(resultTicket);
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

    protected virtual Task<IReadOnlySet<LightweightClaim>> GetCustomClaimsAsync(
        HttpContext httpContext,
        AuthenticationTicket authenticationTicket,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlySet<LightweightClaim> result = new HashSet<LightweightClaim>(LightweightClaim.EqualityComparer);
        return Task.FromResult(result);
    }
}
