using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultErrorPageResult<TRequestContext> : IEndpointHandlerResult<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    public DefaultErrorPageResult(OpenIdentityFrameworkOptions frameworkOptions, string errorId)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(errorId);
        FrameworkOptions = frameworkOptions;
        ErrorId = errorId;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected string ErrorId { get; }

    public virtual Task ExecuteAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        requestContext.HttpContext.Response.Redirect(QueryHelpers.AddQueryString(
            FrameworkOptions.UserInteraction.ErrorUrl,
            BuildParameters()));
        return Task.CompletedTask;
    }

    protected virtual IEnumerable<KeyValuePair<string, string?>> BuildParameters()
    {
        yield return new(FrameworkOptions.UserInteraction.ErrorId, ErrorId);
    }
}
