using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Extensions;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultDirectAuthorizeResult : IEndpointHandlerResult
{
    protected static readonly string AutoSubmitScript = "window.addEventListener('load', function(){document.forms[0].submit();});";

    // echo -n "window.addEventListener('load', function(){document.forms[0].submit();});" | openssl sha256 -binary | openssl base64
    protected static readonly string AutoSubmitScriptHash = $"sha256-{Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(AutoSubmitScript)))}";

    public DefaultDirectAuthorizeResult(
        OpenIdentityFrameworkOptions frameworkOptions,
        HtmlEncoder htmlEncoder,
        IEnumerable<KeyValuePair<string, string?>> parameters,
        string redirectUri,
        string responseMode)
    {
        FrameworkOptions = frameworkOptions;
        HtmlEncoder = htmlEncoder;
        Parameters = parameters;
        RedirectUri = redirectUri;
        ResponseMode = responseMode;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected HtmlEncoder HtmlEncoder { get; }
    protected IEnumerable<KeyValuePair<string, string?>> Parameters { get; }
    protected string RedirectUri { get; }
    protected string ResponseMode { get; }

    public virtual async Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        if (ResponseMode == Constants.Request.Authorize.ResponseMode.Query)
        {
            HandleQueryResponse(httpContext, cancellationToken);
            return;
        }

        if (ResponseMode == Constants.Request.Authorize.ResponseMode.FormPost)
        {
            await HandlePostResponseAsync(httpContext, cancellationToken);
            return;
        }

        throw new InvalidOperationException(
            $"Unexpected response mode. Expected values are: {Constants.Request.Authorize.ResponseMode.Query}, {Constants.Request.Authorize.ResponseMode.FormPost}, but actual was: {ResponseMode}");
    }

    protected virtual void HandleQueryResponse(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        httpContext.Response.SetNoCache();
        var directRedirectUri = QueryHelpers.AddQueryString(
            RedirectUri,
            Parameters);
        httpContext.Response.Redirect(directRedirectUri);
    }

    protected virtual async Task HandlePostResponseAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        httpContext.Response.SetNoCache();
        httpContext.Response.SetNoReferrer();
        httpContext.Response.AddScriptCspHeaders(FrameworkOptions.ContentSecurityPolicy, AutoSubmitScriptHash);
        var html = BuildHtml();
        await httpContext.Response.WriteHtmlAsync(html, cancellationToken);
    }

    protected virtual string BuildHtml()
    {
        var builder = new StringBuilder(32768);
        builder.Append("<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head><body><form method='post' action='");
        builder.Append(HtmlEncoder.Encode(RedirectUri));
        builder.Append("'>");
        foreach (var (key, value) in Parameters)
        {
            builder.Append("<input type='hidden' name='");
            builder.Append(HtmlEncoder.Encode(key));
            builder.Append("' value='");
            if (value != null)
            {
                builder.Append(HtmlEncoder.Encode(value));
            }

            builder.Append("' />\n");
        }

        builder.Append("<noscript><button>Click to continue</button></noscript></form><script>");
        builder.Append(AutoSubmitScript);
        builder.Append("</script></body></html>");
        return builder.ToString();
    }
}
