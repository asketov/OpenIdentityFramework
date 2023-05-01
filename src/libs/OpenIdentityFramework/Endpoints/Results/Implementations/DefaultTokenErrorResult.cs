using System;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Response.Token;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultTokenErrorResult<TRequestContext> : IEndpointHandlerResult<TRequestContext>
    where TRequestContext : AbstractRequestContext
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

    public virtual async Task ExecuteAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        var statusCode = GetStatusCode();
        var response = new ResponseDto(
            ProtocolError.Error,
            FrameworkOptions.ErrorHandling.HideErrorDescriptionsOnSafeAuthorizeErrorResponses ? null : ProtocolError.Description,
            Issuer);
        requestContext.HttpContext.Response.StatusCode = statusCode;
        requestContext.HttpContext.Response.SetNoCache();
        await requestContext.HttpContext.Response.WriteAsJsonAsync(response, cancellationToken);
        await requestContext.HttpContext.Response.Body.FlushAsync(cancellationToken);
    }

    protected virtual int GetStatusCode()
    {
        if (ProtocolError.Error == Errors.InvalidClient)
        {
            return 401;
        }

        return 400;
    }

    protected class ResponseDto
    {
        public ResponseDto(string error, string? errorDescription, string issuer)
        {
            Error = error;
            ErrorDescription = errorDescription;
            Issuer = issuer;
        }

        [JsonPropertyName(ResponseParameters.Error)]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        public string Error { get; }

        [JsonPropertyName(ResponseParameters.ErrorDescription)]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? ErrorDescription { get; }

        [JsonPropertyName(ResponseParameters.Issuer)]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        public string Issuer { get; }
    }
}
