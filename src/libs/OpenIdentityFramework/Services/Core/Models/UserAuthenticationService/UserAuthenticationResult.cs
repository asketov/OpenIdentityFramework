using System;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Services.Core.Models.UserAuthenticationService;

public class UserAuthenticationResult
{
    public UserAuthenticationResult(UserAuthentication userAuthentication)
    {
        ArgumentNullException.ThrowIfNull(userAuthentication);
        IsAuthenticated = true;
        UserAuthentication = userAuthentication;
        HasError = false;
        ErrorDescription = null;
    }

    public UserAuthenticationResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        IsAuthenticated = false;
        UserAuthentication = null;
        HasError = true;
        ErrorDescription = errorDescription;
    }

    public UserAuthenticationResult()
    {
        IsAuthenticated = false;
        UserAuthentication = null;
        HasError = false;
        ErrorDescription = null;
    }

    [MemberNotNullWhen(true, nameof(UserAuthentication))]
    public bool IsAuthenticated { get; }

    public UserAuthentication? UserAuthentication { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    public bool HasError { get; }

    public string? ErrorDescription { get; }
}
