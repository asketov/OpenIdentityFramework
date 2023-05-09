using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Models.Operation.AuthorizeRequestConsent;

public class AuthorizeRequestConsentGranted
{
    public AuthorizeRequestConsentGranted(IReadOnlySet<string> grantedScopes, bool shouldRemember)
    {
        ArgumentNullException.ThrowIfNull(grantedScopes);
        GrantedScopes = grantedScopes;
        ShouldRemember = shouldRemember;
    }

    public IReadOnlySet<string> GrantedScopes { get; }
    public bool ShouldRemember { get; }

    public void Deconstruct(out IReadOnlySet<string> grantedScopes, out bool shouldRemember)
    {
        grantedScopes = GrantedScopes;
        shouldRemember = ShouldRemember;
    }
}
