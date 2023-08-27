using System;

namespace OpenIdentityFramework.Host.Mvc.ViewModels.Consent;

public class ConsentViewModel : ConsentInputViewModel
{
    public string? ReturnUrl { get; set; }

    public string? AuthorizeRequestId { get; set; }
    public ConsentScopeViewModel[] AllScopes { get; set; } = Array.Empty<ConsentScopeViewModel>();
}
