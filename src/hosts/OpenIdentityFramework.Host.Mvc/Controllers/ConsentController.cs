using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Host.Mvc.ViewModels.Consent;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.InMemory.Models.Configuration;
using OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Interaction;

namespace OpenIdentityFramework.Host.Mvc.Controllers;

[Authorize]
public class ConsentController : Controller
{
    private readonly IOpenIdentityFrameworkInteractionService<InMemoryClient, InMemoryClientSecret, InMemoryScope, InMemoryResource, InMemoryResourceSecret, InMemoryResourceOwnerIdentifiers> _interaction;

    public ConsentController(
        IOpenIdentityFrameworkInteractionService<InMemoryClient, InMemoryClientSecret, InMemoryScope, InMemoryResource, InMemoryResourceSecret, InMemoryResourceOwnerIdentifiers> interaction)
    {
        ArgumentNullException.ThrowIfNull(interaction);
        _interaction = interaction;
    }

    [HttpGet]
    public async Task<IActionResult> Index(
        [FromQuery] [Required] string authzId,
        [FromQuery] string? returnUrl,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var vm = await BuildConsentViewModelAsync(authzId, returnUrl, cancellationToken);
        return View(vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Index(
        [FromBody] ConsentInputViewModel model,
        [FromQuery] [Required] string authzId,
        [FromQuery] string? returnUrl,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new NotImplementedException();
    }

    private async Task<ConsentViewModel> BuildConsentViewModelAsync(string authzId, string? returnUrl, CancellationToken cancellationToken)
    {
        var result = new ConsentViewModel();
        if (string.IsNullOrEmpty(authzId))
        {
            throw new InvalidOperationException();
        }

        var authzInfo = await _interaction.GetAuthorizeRequestInformationAsync(HttpContext, authzId, cancellationToken);
        if (authzInfo is null)
        {
            throw new InvalidOperationException();
        }

        var allScopes = new List<ConsentScopeViewModel>();
        foreach (var idTokenScope in authzInfo.RequestedResources.IdTokenScopes)
        {
            allScopes.Add(new()
            {
                Name = idTokenScope.GetScopeId(),
                Required = idTokenScope.IsRequired()
            });
        }

        foreach (var accessTokenScope in authzInfo.RequestedResources.AccessTokenScopes)
        {
            allScopes.Add(new()
            {
                Name = accessTokenScope.GetScopeId(),
                Required = accessTokenScope.IsRequired()
            });
        }

        result.AllScopes = allScopes.ToArray();
        result.AuthorizeRequestId = authzId;
        if (!string.IsNullOrEmpty(returnUrl))
        {
            result.ReturnUrl = Url.IsLocalUrl(returnUrl)
                ? returnUrl
                : Url.Action("Index", "Home");
        }

        return result;
    }

    private async Task<ValidAuthorizeRequest<InMemoryClient, InMemoryClientSecret, InMemoryScope, InMemoryResource, InMemoryResourceSecret>?> GetAuthorizeRequestInformationAsync(string? authzId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrEmpty(authzId))
        {
            return null;
        }

        return await HttpContext.GetAuthorizeRequestInformationAsync<InMemoryClient, InMemoryClientSecret, InMemoryScope, InMemoryResource, InMemoryResourceSecret, InMemoryResourceOwnerIdentifiers>(authzId, cancellationToken);
    }

    private async Task<bool> GrantAsync(string? authzId, AuthorizeRequestConsentGranted grantedConsent, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrEmpty(authzId))
        {
            return false;
        }

        var authenticationResult = await HttpContext.AuthenticateResourceOwnerAsync<InMemoryRequestContext, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>(cancellationToken);
        if (authenticationResult.HasError || !authenticationResult.IsAuthenticated)
        {
            return false;
        }

        await HttpContext.GrantAsync<InMemoryClient, InMemoryClientSecret, InMemoryScope, InMemoryResource, InMemoryResourceSecret, InMemoryResourceOwnerIdentifiers>(
            authzId,
            authenticationResult.Authentication.EssentialClaims.GetResourceOwnerIdentifiers(),
            grantedConsent,
            cancellationToken);
        return true;
    }

    private async Task<bool> DenyAsync(string? authzId, AuthorizeRequestConsentDenied deniedConsent, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrEmpty(authzId))
        {
            return false;
        }

        var authenticationResult = await HttpContext.AuthenticateResourceOwnerAsync<InMemoryRequestContext, InMemoryResourceOwnerEssentialClaims, InMemoryResourceOwnerIdentifiers>(cancellationToken);
        if (authenticationResult.HasError || !authenticationResult.IsAuthenticated)
        {
            return false;
        }

        await HttpContext.DenyAsync<InMemoryClient, InMemoryClientSecret, InMemoryScope, InMemoryResource, InMemoryResourceSecret, InMemoryResourceOwnerIdentifiers>(
            authzId,
            authenticationResult.Authentication.EssentialClaims.GetResourceOwnerIdentifiers(),
            deniedConsent,
            cancellationToken);
        return true;
    }
}
