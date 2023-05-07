using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Response;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultTokenErrorResult : IEndpointHandlerResult
{
    public DefaultTokenErrorResult(OpenIdentityFrameworkOptions frameworkOptions, ProtocolError protocolError, string issuer)
    {
        FrameworkOptions = frameworkOptions;
        ProtocolError = protocolError;
        Issuer = issuer;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected ProtocolError ProtocolError { get; }
    protected string Issuer { get; }

    public virtual async Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        var statusCode = GetStatusCode();
        var response = new ResponseDto(
            ProtocolError.Error,
            FrameworkOptions.ErrorHandling.HideErrorDescriptionsOnSafeAuthorizeErrorResponses ? null : ProtocolError.Description,
            Issuer);
        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.SetNoCache();
        await httpContext.Response.WriteAsJsonAsync(response, cancellationToken);
        await httpContext.Response.Body.FlushAsync(cancellationToken);
    }

    protected virtual int GetStatusCode()
    {
        if (ProtocolError.Error == TokenErrors.InvalidClient)
        {
            return 401;
        }

        return 400;
    }

    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    protected class ResponseDto
    {
        public ResponseDto(string error, string? errorDescription, string issuer)
        {
            Error = error;
            ErrorDescription = errorDescription;
            Issuer = issuer;
        }

        [JsonPropertyName(TokenResponseParameters.Error)]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        public string Error { get; }

        [JsonPropertyName(TokenResponseParameters.ErrorDescription)]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? ErrorDescription { get; }

        [JsonPropertyName(TokenResponseParameters.Issuer)]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        public string Issuer { get; }
    }
}
