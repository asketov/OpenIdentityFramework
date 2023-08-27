using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIdentityFramework.Host.Mvc.Constants;
using OpenIdentityFramework.Host.Mvc.Services.Local;
using OpenIdentityFramework.Host.Mvc.ViewModels.Account;
using OpenIdentityFramework.InMemory.Models.Authentication;
using OpenIdentityFramework.InMemory.Models.Configuration;
using OpenIdentityFramework.Services.Interaction;

namespace OpenIdentityFramework.Host.Mvc.Controllers;

public class AccountController : Controller
{
    private readonly ILocalUserClaimsPrincipalFactory _claimsPrincipalFactory;
    private readonly IOpenIdentityFrameworkInteractionService<InMemoryClient, InMemoryClientSecret, InMemoryScope, InMemoryResource, InMemoryResourceSecret, InMemoryResourceOwnerIdentifiers> _interaction;
    private readonly ILocalUserService _users;

    public AccountController(
        ILocalUserService users,
        ILocalUserClaimsPrincipalFactory claimsPrincipalFactory,
        IOpenIdentityFrameworkInteractionService<InMemoryClient, InMemoryClientSecret, InMemoryScope, InMemoryResource, InMemoryResourceSecret, InMemoryResourceOwnerIdentifiers> interaction)
    {
        ArgumentNullException.ThrowIfNull(users);
        ArgumentNullException.ThrowIfNull(claimsPrincipalFactory);
        ArgumentNullException.ThrowIfNull(interaction);
        _users = users;
        _claimsPrincipalFactory = claimsPrincipalFactory;
        _interaction = interaction;
    }

    [HttpGet]
    public async Task<IActionResult> Login([FromQuery] string? authzId, [FromQuery] string? returnUrl, CancellationToken cancellationToken)
    {
        var vm = await BuildViewModelAsync(authzId, true, returnUrl, cancellationToken);
        return View(vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login([FromForm] LoginInputViewModel model, [FromQuery] string? returnUrl, [FromQuery] string? authzId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ModelState.IsValid)
        {
            var vm = await BuildViewModelAsync(authzId, false, returnUrl, cancellationToken);
            return View(vm);
        }

        ArgumentNullException.ThrowIfNull(model);
        var user = await _users.FindByLoginAndPasswordAsync(model.Login, model.Password, cancellationToken);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Incorrect login or password");
            var vm = await BuildViewModelAsync(authzId, false, returnUrl, cancellationToken);
            return View(vm);
        }

        var properties = new AuthenticationProperties();
        if (model.RememberMe)
        {
            properties.IsPersistent = true;
        }

        properties.RedirectUri = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl)
            ? returnUrl
            : Url.Action("Index", "Home");
        var principal = _claimsPrincipalFactory.CreateClaimsPrincipal(user);
        return SignIn(principal, properties, LocalAuthenticationSchemes.Cookies);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Logout([FromQuery] string? returnUrl)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl)
                ? returnUrl
                : Url.Action("Index", "Home")
        };
        return SignOut(properties, LocalAuthenticationSchemes.Cookies);
    }

    private async Task<LoginViewModel> BuildViewModelAsync(string? authzId, bool fillHint, string? returnUrl, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new LoginViewModel();
        if (!string.IsNullOrEmpty(authzId))
        {
            var authzInfo = await _interaction.GetAuthorizeRequestInformationAsync(HttpContext, authzId, cancellationToken);
            if (authzInfo is not null)
            {
                if (!string.IsNullOrEmpty(authzInfo.LoginHint) && fillHint)
                {
                    result.Login = authzInfo.LoginHint;
                }

                result.AuthorizeRequestId = authzId;
            }
        }

        if (!string.IsNullOrEmpty(returnUrl))
        {
            result.ReturnUrl = Url.IsLocalUrl(returnUrl)
                ? returnUrl
                : Url.Action("Index", "Home");
        }

        return result;
    }
}
