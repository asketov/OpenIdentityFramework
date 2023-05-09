using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Services.Endpoints.Jwks.Model;

public class JwkSetMetadata
{
    public JwkSetMetadata(IReadOnlyCollection<JsonWebKeyMetadata> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        Keys = keys;
    }

    public IReadOnlyCollection<JsonWebKeyMetadata> Keys { get; }
}
