using System;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

public class ValidRefreshToken<TRefreshToken>
    where TRefreshToken : AbstractRefreshToken
{
    public ValidRefreshToken(string handle, TRefreshToken token)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(token);
        Handle = handle;
        Token = token;
    }

    public string Handle { get; }
    public TRefreshToken Token { get; }
}
