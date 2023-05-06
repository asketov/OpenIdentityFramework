using System.Collections.Generic;
using Microsoft.Extensions.Primitives;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;

public class AuthorizeRequestParametersToValidate
{
    public AuthorizeRequestParametersToValidate(IReadOnlyDictionary<string, StringValues> raw, bool isOpenIdRequest)
    {
        Raw = raw;
        IsOpenIdRequest = isOpenIdRequest;
    }

    public IReadOnlyDictionary<string, StringValues> Raw { get; }

    public bool IsOpenIdRequest { get; }
}
