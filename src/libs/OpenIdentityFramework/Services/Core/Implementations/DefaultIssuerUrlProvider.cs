using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultIssuerUrlProvider<TRequestContext>
    : IIssuerUrlProvider<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    public Task<string> GetIssuerAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(requestContext);
        var result = requestContext.HttpContext.Request.Scheme + Uri.SchemeDelimiter + requestContext.HttpContext.Request.Host + requestContext.HttpContext.Request.PathBase;
        return Task.FromResult(result);
    }
}
