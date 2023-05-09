using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Endpoints.Results.Implementations;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Endpoints.Jwks;

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultJwksEndpointHandler<TRequestContext>
    : IJwksEndpointHandler<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    public DefaultJwksEndpointHandler(OpenIdentityFrameworkOptions frameworkOptions, IJwksResponseGenerator<TRequestContext> jwksResponseGenerator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(jwksResponseGenerator);
        FrameworkOptions = frameworkOptions;
        JwksResponseGenerator = jwksResponseGenerator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IJwksResponseGenerator<TRequestContext> JwksResponseGenerator { get; }

    public virtual async Task<IEndpointHandlerResult> HandleAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        if (!HttpMethods.IsGet(requestContext.HttpContext.Request.Method))
        {
            return new DefaultStatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var jwkSet = await JwksResponseGenerator.CreateJwkSetAsync(requestContext, cancellationToken);
        return new DefaultJwkDocumentResult(FrameworkOptions, jwkSet);
    }
}
