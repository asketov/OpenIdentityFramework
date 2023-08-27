using System;
using OpenIdentityFramework.Host.Mvc.ViewModels.Consent.Enums;

namespace OpenIdentityFramework.Host.Mvc.ViewModels.Consent;

public class ConsentInputViewModel
{
    public string[] CheckedScopes { get; set; } = Array.Empty<string>();

    public bool Remember { get; set; }

    public ConsentAction Action { get; set; } = ConsentAction.Deny;
}
