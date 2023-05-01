using System;

namespace OpenIdentityFramework.Services.Core.Models.IdTokenService;

public class CreatedIdToken
{
    public CreatedIdToken(string handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        Handle = handle;
    }

    public string Handle { get; }
}
