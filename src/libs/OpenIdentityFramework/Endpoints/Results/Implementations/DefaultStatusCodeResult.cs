﻿using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultStatusCodeResult : IEndpointHandlerResult
{
    public DefaultStatusCodeResult(HttpStatusCode httpStatusCode)
    {
        StatusCode = httpStatusCode;
    }

    protected HttpStatusCode StatusCode { get; }

    public virtual Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        httpContext.Response.StatusCode = (int) StatusCode;
        return Task.CompletedTask;
    }
}
