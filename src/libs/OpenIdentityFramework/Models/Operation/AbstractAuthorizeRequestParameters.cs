using System;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractAuthorizeRequestParameters
{
    public abstract DateTimeOffset GetInitialRequestDate();
    public abstract IReadOnlyDictionary<string, StringValues> GetAuthorizeRequestParameters();
    public abstract DateTimeOffset GetCreationDate();
    public abstract DateTimeOffset GetExpirationDate();
}
