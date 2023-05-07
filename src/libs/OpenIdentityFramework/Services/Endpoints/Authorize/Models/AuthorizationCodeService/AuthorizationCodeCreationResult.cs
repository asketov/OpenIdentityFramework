using System;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;

public class AuthorizationCodeCreationResult
{
    public AuthorizationCodeCreationResult(string handle, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        Handle = handle;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    public string Handle { get; }

    public DateTimeOffset IssuedAt { get; }

    public DateTimeOffset ExpiresAt { get; }
}
