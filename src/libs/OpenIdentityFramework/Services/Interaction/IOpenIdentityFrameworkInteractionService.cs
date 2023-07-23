using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

namespace OpenIdentityFramework.Services.Interaction;

public interface IOpenIdentityFrameworkInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerIdentifiers>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>?> GetAuthorizeRequestInformationAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        CancellationToken cancellationToken);

    Task GrantAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentGranted grantedConsent,
        CancellationToken cancellationToken);

    Task DenyAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        TResourceOwnerIdentifiers authorIdentifiers,
        AuthorizeRequestConsentDenied deniedConsent,
        CancellationToken cancellationToken);
}
