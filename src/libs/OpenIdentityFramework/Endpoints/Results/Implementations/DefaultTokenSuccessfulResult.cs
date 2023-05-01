using System;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Response.Token;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenResponseGenerator;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultTokenSuccessfulResult<TRequestContext> : IEndpointHandlerResult<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    public DefaultTokenSuccessfulResult(OpenIdentityFrameworkOptions frameworkOptions, SuccessfulTokenResponse successfulTokenResponse)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(successfulTokenResponse);
        FrameworkOptions = frameworkOptions;
        SuccessfulTokenResponse = successfulTokenResponse;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected SuccessfulTokenResponse SuccessfulTokenResponse { get; }

    public virtual async Task ExecuteAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        var response = new ResponseDto(
            SuccessfulTokenResponse.AccessToken,
            SuccessfulTokenResponse.IssuedTokenType,
            SuccessfulTokenResponse.RefreshToken,
            SuccessfulTokenResponse.ExpiresIn,
            SuccessfulTokenResponse.IdToken,
            SuccessfulTokenResponse.Scope,
            SuccessfulTokenResponse.Issuer);
        requestContext.HttpContext.Response.StatusCode = 200;
        requestContext.HttpContext.Response.SetNoCache();
        await requestContext.HttpContext.Response.WriteAsJsonAsync(response, cancellationToken);
        await requestContext.HttpContext.Response.Body.FlushAsync(cancellationToken);
    }

    protected class ResponseDto
    {
        public ResponseDto(string accessToken, string tokenType, string? refreshToken, long expiresIn, string? idToken, string? scope, string issuer)
        {
            AccessToken = accessToken;
            TokenType = tokenType;
            RefreshToken = refreshToken;
            ExpiresIn = expiresIn;
            IdToken = idToken;
            Scope = scope;
            Issuer = issuer;
        }

        [JsonPropertyName(ResponseParameters.AccessToken)]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string AccessToken { get; }

        [JsonPropertyName(ResponseParameters.TokenType)]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string TokenType { get; }

        [JsonPropertyName(ResponseParameters.RefreshToken)]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? RefreshToken { get; }

        [JsonPropertyName(ResponseParameters.ExpiresIn)]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        public long ExpiresIn { get; }

        [JsonPropertyName(ResponseParameters.IdToken)]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? IdToken { get; }

        [JsonPropertyName(ResponseParameters.Scope)]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Scope { get; }

        [JsonPropertyName(ResponseParameters.Issuer)]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Issuer { get; }
    }
}
