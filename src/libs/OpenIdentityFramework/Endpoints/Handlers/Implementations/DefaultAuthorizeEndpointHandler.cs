using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Endpoints.Results.Implementations;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Services.Core;

namespace OpenIdentityFramework.Endpoints.Handlers.Implementations;

public class DefaultAuthorizeEndpointHandler : IAuthorizeEndpointHandler
{
    public DefaultAuthorizeEndpointHandler(
        OpenIdentityFrameworkOptions frameworkOptions,
        IIssuerUrlProvider issuerUrlProvider)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(issuerUrlProvider);
        FrameworkOptions = frameworkOptions;
        IssuerUrlProvider = issuerUrlProvider;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IIssuerUrlProvider IssuerUrlProvider { get; }

    public virtual async Task<IEndpointHandlerResult> HandleAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyDictionary<string, StringValues> parameters;
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // The authorization server MUST support the use of the HTTP GET method Section 9.3.1 of [RFC9110] for the authorization endpoint
        // and MAY support the POST method (Section 9.3.3 of RFC9110) as well.
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // Authorization Servers MUST support the use of the HTTP GET and POST methods defined in RFC 2616 [RFC2616] at the Authorization Endpoint.
        // Clients MAY use the HTTP GET or POST methods to send the Authorization Request to the Authorization Server.
        // If using the HTTP GET method, the request parameters are serialized using URI Query String Serialization, per Section 13.1.
        // If using the HTTP POST method, the request parameters are serialized using Form Serialization, per Section 13.2.
        if (HttpMethods.IsGet(httpContext.Request.Method))
        {
            parameters = httpContext.Request.Query.AsReadOnlyDictionary();
        }
        else if (HttpMethods.IsPost(httpContext.Request.Method))
        {
            if (!httpContext.Request.HasApplicationFormContentType())
            {
                return new DefaultStatusCodeResult(HttpStatusCode.UnsupportedMediaType);
            }

            var form = await httpContext.Request.ReadFormAsync(cancellationToken);
            parameters = form.AsReadOnlyDictionary();
        }
        else
        {
            return new DefaultStatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var issuer = await IssuerUrlProvider.GetIssuerAsync(httpContext, cancellationToken);

        throw new NotImplementedException();
    }
}
