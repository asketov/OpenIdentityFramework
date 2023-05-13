using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;

public class ResourceOwnerAuthenticationResult<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public ResourceOwnerAuthenticationResult(ResourceOwnerAuthentication<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> authentication)
    {
        ArgumentNullException.ThrowIfNull(authentication);
        IsAuthenticated = true;
        Authentication = authentication;
        HasError = false;
        ErrorDescription = null;
    }

    public ResourceOwnerAuthenticationResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        IsAuthenticated = false;
        Authentication = null;
        HasError = true;
        ErrorDescription = errorDescription;
    }

    public ResourceOwnerAuthenticationResult()
    {
        IsAuthenticated = false;
        Authentication = null;
        HasError = false;
        ErrorDescription = null;
    }

    [MemberNotNullWhen(true, nameof(Authentication))]
    public bool IsAuthenticated { get; }

    public ResourceOwnerAuthentication<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? Authentication { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    public bool HasError { get; }

    public string? ErrorDescription { get; }
}
