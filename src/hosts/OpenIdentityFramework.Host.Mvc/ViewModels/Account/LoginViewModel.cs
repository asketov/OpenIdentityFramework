namespace OpenIdentityFramework.Host.Mvc.ViewModels.Account;

public class LoginViewModel : LoginInputViewModel
{
    public string? ReturnUrl { get; set; }

    public string? AuthorizeRequestId { get; set; }
}
