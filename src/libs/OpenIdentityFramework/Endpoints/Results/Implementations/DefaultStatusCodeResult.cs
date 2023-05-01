using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultStatusCodeResult<TRequestContext> : IEndpointHandlerResult<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    public DefaultStatusCodeResult(HttpStatusCode httpStatusCode)
    {
        StatusCode = httpStatusCode;
    }

    protected HttpStatusCode StatusCode { get; }

    public virtual Task ExecuteAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        requestContext.HttpContext.Response.StatusCode = (int) StatusCode;
        return Task.CompletedTask;
    }
}
