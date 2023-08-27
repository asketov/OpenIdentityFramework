using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;
using OpenIdentityFramework.Services.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    : IResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultResourceOwnerAuthenticationService(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthenticationSchemeProvider schemeProvider,
        IResourceOwnerEssentialClaimsProvider<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> essentialClaimsProvider)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(schemeProvider);
        ArgumentNullException.ThrowIfNull(essentialClaimsProvider);
        FrameworkOptions = frameworkOptions;
        SchemeProvider = schemeProvider;
        EssentialClaimsProvider = essentialClaimsProvider;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IAuthenticationSchemeProvider SchemeProvider { get; }
    protected IResourceOwnerEssentialClaimsProvider<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> EssentialClaimsProvider { get; }

    public virtual async Task<ResourceOwnerAuthenticationResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> AuthenticateAsync(TRequestContext requestContext, CancellationToken cancellationToken)
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

    protected virtual async Task<ResourceOwnerAuthenticationResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> HandleAuthenticateResultAsync(
        TRequestContext requestContext,
        AuthenticateResult? authenticateResult,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (authenticateResult is null || !authenticateResult.Succeeded || authenticateResult.Ticket.Principal.Identity?.IsAuthenticated != true)
        {
            return new();
        }

        var claimsResult = await EssentialClaimsProvider.GetAsync(requestContext, authenticateResult.Ticket, cancellationToken);
        if (claimsResult.HasError)
        {
            return new(claimsResult.ErrorDescription);
        }

        return new(new ResourceOwnerAuthentication<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>(claimsResult.EssentialClaims, authenticateResult.Ticket));
    }
}
