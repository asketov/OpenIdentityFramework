using System;

namespace OpenIdentityFramework.Services.Core.Models.RefreshTokenService;

public class CreatedRefreshToken
{
    public CreatedRefreshToken(string handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        Handle = handle;
    }

    public string Handle { get; }
}
