using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Interaction;
using OpenIdentityFramework.Services.Operation;

namespace OpenIdentityFramework.Extensions;

public static class HttpContextExtensions
{
    public static async Task<ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>?> GetAuthorizeRequestInformationAsync<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerIdentifiers>(
        this HttpContext httpContext,
        string authorizeRequestId,
        CancellationToken cancellationToken)
        where TClient : AbstractClient<TClientSecret>
        where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
        where TScope : AbstractScope
        where TResource : AbstractResource<TResourceSecret>
        where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
        where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers

    {
        ArgumentNullException.ThrowIfNull(httpContext);
        var interactionService = httpContext.RequestServices.GetRequiredService<IOpenIdentityFrameworkInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerIdentifiers>>();
        return await interactionService.GetAuthorizeRequestInformationAsync(httpContext, authorizeRequestId, cancellationToken);
    }

    public static async Task GrantAsync<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerIdentifiers>(
        this HttpContext httpContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentGranted grantedConsent,
        CancellationToken cancellationToken)
        where TClient : AbstractClient<TClientSecret>
        where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
        where TScope : AbstractScope
        where TResource : AbstractResource<TResourceSecret>
        where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
        where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers

    {
        ArgumentNullException.ThrowIfNull(httpContext);
        var interactionService = httpContext.RequestServices.GetRequiredService<IOpenIdentityFrameworkInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerIdentifiers>>();
        await interactionService.GrantAsync(httpContext, authorizeRequestId, authorIdentifiers, grantedConsent, cancellationToken);
    }

    public static async Task DenyAsync<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerIdentifiers>(
        this HttpContext httpContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentDenied deniedConsent,
        CancellationToken cancellationToken)
        where TClient : AbstractClient<TClientSecret>
        where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
        where TScope : AbstractScope
        where TResource : AbstractResource<TResourceSecret>
        where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
        where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers

    {
        ArgumentNullException.ThrowIfNull(httpContext);
        var interactionService = httpContext.RequestServices.GetRequiredService<IOpenIdentityFrameworkInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerIdentifiers>>();
        await interactionService.DenyAsync(httpContext, authorizeRequestId, authorIdentifiers, deniedConsent, cancellationToken);
    }

    public static async Task<ResourceOwnerAuthenticationResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> AuthenticateResourceOwnerAsync<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>(
        this HttpContext httpContext,
        CancellationToken cancellationToken)
        where TRequestContext : class, IRequestContext
        where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
        where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        var contextFactory = httpContext.RequestServices.GetRequiredService<IRequestContextFactory<TRequestContext>>();
        await using var requestContext = await contextFactory.CreateAsync(httpContext, cancellationToken);
        var authenticationService = httpContext.RequestServices.GetRequiredService<IResourceOwnerAuthenticationService<TRequestContext, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>>();
        return await authenticationService.AuthenticateAsync(requestContext, cancellationToken);
    }
}
