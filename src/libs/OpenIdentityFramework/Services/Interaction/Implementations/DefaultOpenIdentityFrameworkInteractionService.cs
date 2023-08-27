using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Operation;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Interaction.Implementations;

public class DefaultOpenIdentityFrameworkInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerIdentifiers, TRequestContext, TAuthorizeRequest, TAuthorizeRequestConsent>
    : IOpenIdentityFrameworkInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerIdentifiers>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
    where TRequestContext : class, IRequestContext
    where TAuthorizeRequest : AbstractAuthorizeRequest
    where TAuthorizeRequestConsent : AbstractAuthorizeRequestConsent<TResourceOwnerIdentifiers>
{
    public DefaultOpenIdentityFrameworkInteractionService(
        IIssuerUrlProvider<TRequestContext> issuerUrlProvider,
        IAuthorizeRequestService<TRequestContext, TAuthorizeRequest> authorizeRequest,
        IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> requestValidator,
        IAuthorizeRequestConsentStorage<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers> authorizeRequestConsentStorage)
    {
        ArgumentNullException.ThrowIfNull(issuerUrlProvider);
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(requestValidator);
        ArgumentNullException.ThrowIfNull(authorizeRequestConsentStorage);
        IssuerUrlProvider = issuerUrlProvider;
        AuthorizeRequest = authorizeRequest;
        RequestValidator = requestValidator;
        AuthorizeRequestConsentStorage = authorizeRequestConsentStorage;
    }

    protected IIssuerUrlProvider<TRequestContext> IssuerUrlProvider { get; }
    protected IAuthorizeRequestService<TRequestContext, TAuthorizeRequest> AuthorizeRequest { get; }
    protected IAuthorizeRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> RequestValidator { get; }
    protected IAuthorizeRequestConsentStorage<TRequestContext, TAuthorizeRequestConsent, TResourceOwnerIdentifiers> AuthorizeRequestConsentStorage { get; }

    public virtual async Task<ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>?> GetAuthorizeRequestInformationAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(httpContext);
        var contextFactory = httpContext.RequestServices.GetRequiredService<IRequestContextFactory<TRequestContext>>();
        await using var requestContext = await contextFactory.CreateAsync(httpContext, cancellationToken);
        var result = await GetAuthorizeRequestInformationAsync(requestContext, authorizeRequestId, cancellationToken);
        await requestContext.CommitAsync(httpContext.RequestAborted);
        return result;
    }

    public virtual async Task GrantAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentGranted grantedConsent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(httpContext);
        var contextFactory = httpContext.RequestServices.GetRequiredService<IRequestContextFactory<TRequestContext>>();
        await using var requestContext = await contextFactory.CreateAsync(httpContext, cancellationToken);
        await GrantAsync(requestContext, authorizeRequestId, authorIdentifiers, grantedConsent, cancellationToken);
        await requestContext.CommitAsync(httpContext.RequestAborted);
    }

    public virtual async Task DenyAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentDenied deniedConsent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(httpContext);
        var contextFactory = httpContext.RequestServices.GetRequiredService<IRequestContextFactory<TRequestContext>>();
        await using var requestContext = await contextFactory.CreateAsync(httpContext, cancellationToken);
        await DenyAsync(requestContext, authorizeRequestId, authorIdentifiers, deniedConsent, cancellationToken);
        await requestContext.CommitAsync(httpContext.RequestAborted);
    }

    protected virtual async Task<ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>?> GetAuthorizeRequestInformationAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var issuer = await IssuerUrlProvider.GetIssuerAsync(requestContext, cancellationToken);
        var authorizeRequest = await AuthorizeRequest.FindAsync(requestContext, authorizeRequestId, cancellationToken);
        if (authorizeRequest is null)
        {
            return null;
        }

        var validationResult = await RequestValidator.ValidateAsync(
            requestContext,
            authorizeRequest.GetAuthorizeRequestParameters(),
            authorizeRequest.GetInitialRequestDate(),
            issuer,
            cancellationToken);
        if (validationResult.HasError)
        {
            await AuthorizeRequest.DeleteAsync(requestContext, authorizeRequestId, cancellationToken);
            return null;
        }

        return validationResult.ValidRequest;
    }

    protected virtual async Task GrantAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentGranted grantedConsent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var authorizeRequest = await AuthorizeRequest.FindAsync(requestContext, authorizeRequestId, cancellationToken);
        if (authorizeRequest is null)
        {
            return;
        }

        var createdAt = authorizeRequest.GetCreationDate();
        var expiresAt = authorizeRequest.GetExpirationDate();
        await AuthorizeRequestConsentStorage.GrantAsync(requestContext, authorizeRequestId, authorIdentifiers, grantedConsent, createdAt, expiresAt, cancellationToken);
    }

    protected virtual async Task DenyAsync(
        TRequestContext requestContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentDenied deniedConsent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var authorizeRequest = await AuthorizeRequest.FindAsync(requestContext, authorizeRequestId, cancellationToken);
        if (authorizeRequest is null)
        {
            return;
        }

        var createdAt = authorizeRequest.GetCreationDate();
        var expiresAt = authorizeRequest.GetExpirationDate();
        await AuthorizeRequestConsentStorage.DenyAsync(requestContext, authorizeRequestId, authorIdentifiers, deniedConsent, createdAt, expiresAt, cancellationToken);
    }
}
