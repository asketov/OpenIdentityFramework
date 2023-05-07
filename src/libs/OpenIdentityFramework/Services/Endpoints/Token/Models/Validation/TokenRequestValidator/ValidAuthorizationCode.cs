using System;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

public class ValidAuthorizationCode<TAuthorizationCode>
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public ValidAuthorizationCode(string handle, TAuthorizationCode code)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(code);
        Handle = handle;
        Code = code;
    }

    public string Handle { get; }
    public TAuthorizationCode Code { get; }
}
