using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultIssuerUrlProvider : IIssuerUrlProvider
{
    public virtual Task<string> GetIssuerAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        var result = httpContext.Request.Scheme + Uri.SchemeDelimiter + httpContext.Request.Host + httpContext.Request.PathBase;
        return Task.FromResult(result);
    }
}
