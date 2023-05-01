using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultLoginUserPageResult<TRequestContext> : IEndpointHandlerResult<TRequestContext>
    where TRequestContext : AbstractRequestContext
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

    public virtual Task ExecuteAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        requestContext.HttpContext.Response.Redirect(QueryHelpers.AddQueryString(
            FrameworkOptions.UserInteraction.LoginUrl,
            BuildParameters()));
        return Task.CompletedTask;
    }

    protected virtual IEnumerable<KeyValuePair<string, string?>> BuildParameters()
    {
        yield return new(FrameworkOptions.UserInteraction.AuthorizeRequestIdParameterName, AuthorizeRequestId);
    }
}
