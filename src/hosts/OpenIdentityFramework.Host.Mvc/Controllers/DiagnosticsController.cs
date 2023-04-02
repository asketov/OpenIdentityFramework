using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace OpenIdentityFramework.Host.Mvc.Controllers;

public class DiagnosticsController : Controller
{
    public async Task<IActionResult> Index()
    {
        var authentication = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
        return View(authentication);
    }
}
