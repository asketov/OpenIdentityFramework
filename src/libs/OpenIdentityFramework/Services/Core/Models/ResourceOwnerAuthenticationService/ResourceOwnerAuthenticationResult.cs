using System;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;

public class ResourceOwnerAuthenticationResult
{
    public ResourceOwnerAuthenticationResult(ResourceOwnerAuthentication authentication)
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

    public ResourceOwnerAuthentication? Authentication { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    public bool HasError { get; }

    public string? ErrorDescription { get; }
}
