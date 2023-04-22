using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using OpenIdentityFramework.Configuration.Options;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultLoginUserPageResult : IEndpointHandlerResult
{
    public DefaultLoginUserPageResult(OpenIdentityFrameworkOptions frameworkOptions, string authorizeRequestId)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(authorizeRequestId);
        FrameworkOptions = frameworkOptions;
        AuthorizeRequestId = authorizeRequestId;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected string AuthorizeRequestId { get; }

    public virtual Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        httpContext.Response.Redirect(QueryHelpers.AddQueryString(
            FrameworkOptions.UserInteraction.LoginUrl,
            BuildParameters()));
        return Task.CompletedTask;
    }

    protected virtual IEnumerable<KeyValuePair<string, string?>> BuildParameters()
    {
        yield return new(FrameworkOptions.UserInteraction.AuthorizeRequestId, AuthorizeRequestId);
    }
}
