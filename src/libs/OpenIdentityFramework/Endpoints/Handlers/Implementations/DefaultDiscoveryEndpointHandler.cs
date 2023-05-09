using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Endpoints.Results.Implementations;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Discovery;

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultDiscoveryEndpointHandler<TRequestContext>
    : IDiscoveryEndpointHandler<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    public DefaultDiscoveryEndpointHandler(
        OpenIdentityFrameworkOptions frameworkOptions,
        IIssuerUrlProvider<TRequestContext> issuerUrlProvider,
        IDiscoveryResponseGenerator<TRequestContext> responseGenerator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(issuerUrlProvider);
        ArgumentNullException.ThrowIfNull(responseGenerator);
        FrameworkOptions = frameworkOptions;
        IssuerUrlProvider = issuerUrlProvider;
        ResponseGenerator = responseGenerator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IIssuerUrlProvider<TRequestContext> IssuerUrlProvider { get; }
    protected IDiscoveryResponseGenerator<TRequestContext> ResponseGenerator { get; }

    public virtual async Task<IEndpointHandlerResult> HandleAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        if (!HttpMethods.IsGet(requestContext.HttpContext.Request.Method))
        {
            return new DefaultStatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var issuer = await IssuerUrlProvider.GetIssuerAsync(requestContext, cancellationToken);
        var discoveryDocument = await ResponseGenerator.CreateDiscoveryDocumentAsync(requestContext, issuer, cancellationToken);
        return new DefaultDiscoveryDocumentResult(FrameworkOptions, discoveryDocument);
    }
}
