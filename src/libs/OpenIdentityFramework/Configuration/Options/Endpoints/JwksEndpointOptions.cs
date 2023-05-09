using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options.Endpoints;

[SuppressMessage("ReSharper", "IdentifierTypo")]
public class JwksEndpointOptions
{
    public string Path { get; set; } = DefaultRoutes.Jwks;

    public TimeSpan? ResponseHttpCacheInterval { get; set; }
    public TimeSpan? JwksDocumentInMemoryCacheInterval { get; set; } = TimeSpan.FromMinutes(1);
}
