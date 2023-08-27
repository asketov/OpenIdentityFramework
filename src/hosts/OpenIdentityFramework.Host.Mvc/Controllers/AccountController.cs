using System;
using System.Threading;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIdentityFramework.Host.Mvc.Constants;
using OpenIdentityFramework.Host.Mvc.Services.Local;
using OpenIdentityFramework.Host.Mvc.ViewModels;

namespace OpenIdentityFramework.Host.Mvc.Controllers;

public class AccountController : Controller
{
    private readonly ILocalUserClaimsPrincipalFactory _claimsPrincipalFactory;
    private readonly ILocalUserService _users;


    public AccountController(ILocalUserService users, ILocalUserClaimsPrincipalFactory claimsPrincipalFactory)
    {
        ArgumentNullException.ThrowIfNull(users);
        ArgumentNullException.ThrowIfNull(claimsPrincipalFactory);
        _users = users;
        _claimsPrincipalFactory = claimsPrincipalFactory;
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Login(LoginViewModel model, string? returnUrl, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (model is null)
        {
            return View();
        }

        if (!ModelState.IsValid)
        {
            return View();
        }

        var user = _users.FindByLoginAndPassword(model.Login, model.Password);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Incorrect login or password");
            return View();
        }

        var properties = new AuthenticationProperties();
        if (model.RememberMe)
        {
            properties.IsPersistent = true;
        }

        if (returnUrl is not null && Url.IsLocalUrl(returnUrl))
        {
            properties.RedirectUri = returnUrl;
        }
        else
        {
            properties.RedirectUri = Url.Action("Index", "Home");
        }

        var principal = _claimsPrincipalFactory.CreateClaimsPrincipal(user);
        return SignIn(principal, properties, LocalAuthenticationSchemes.Cookies);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Logout(string? returnUrl)
    {
        var properties = new AuthenticationProperties();
        if (returnUrl is not null && Url.IsLocalUrl(returnUrl))
        {
            properties.RedirectUri = returnUrl;
        }
        else
        {
            properties.RedirectUri = Url.Action("Index", "Home");
        }

        return SignOut(properties, LocalAuthenticationSchemes.Cookies);
    }
}
