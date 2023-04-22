using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using OpenIdentityFramework.Configuration.Options;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultErrorPageResult : IEndpointHandlerResult
{
    public DefaultErrorPageResult(OpenIdentityFrameworkOptions frameworkOptions, string errorId)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(errorId);
        FrameworkOptions = frameworkOptions;
        ErrorId = errorId;
    }

    protected virtual OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected virtual string ErrorId { get; }

    public Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        httpContext.Response.Redirect(QueryHelpers.AddQueryString(
            FrameworkOptions.UserInteraction.ErrorUrl,
            BuildParameters()));
        return Task.CompletedTask;
    }

    protected virtual IEnumerable<KeyValuePair<string, string?>> BuildParameters()
    {
        yield return new(FrameworkOptions.UserInteraction.ErrorId, ErrorId);
    }
}
