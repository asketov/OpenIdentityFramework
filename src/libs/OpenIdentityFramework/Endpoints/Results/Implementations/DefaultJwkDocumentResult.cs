using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Response;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Services.Endpoints.Jwks.Model;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultJwkDocumentResult : IEndpointHandlerResult
{
    public DefaultJwkDocumentResult(OpenIdentityFrameworkOptions frameworkOptions, JwkSetMetadata jwkSetMetadata)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(jwkSetMetadata);
        FrameworkOptions = frameworkOptions;
        JwkSetMetadata = jwkSetMetadata;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected JwkSetMetadata JwkSetMetadata { get; }

    public virtual async Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        var response = BuildResponseParameter();
        if (FrameworkOptions.Endpoints.Jwks.ResponseHttpCacheInterval.HasValue)
        {
            httpContext.Response.SetCache(FrameworkOptions.Endpoints.Jwks.ResponseHttpCacheInterval.Value);
        }

        await httpContext.Response.WriteAsJsonAsync(response, cancellationToken);
        await httpContext.Response.Body.FlushAsync(cancellationToken);
    }

    protected virtual JwksResult BuildResponseParameter()
    {
        var resultKeys = new List<Dictionary<string, object>>(JwkSetMetadata.Keys.Count);
        foreach (var keyMetadata in JwkSetMetadata.Keys)
        {
            var key = BuildKey(keyMetadata);
            resultKeys.Add(key);
        }

        return new(resultKeys);
    }

    protected virtual Dictionary<string, object> BuildKey(JsonWebKeyMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        var result = new Dictionary<string, object>
        {
            [JwksResponseParameters.KeyType] = metadata.KeyType
        };
        if (!string.IsNullOrEmpty(metadata.PublicKeyUse))
        {
            result[JwksResponseParameters.PublicKeyUse] = metadata.PublicKeyUse;
        }

        if (!string.IsNullOrEmpty(metadata.Algorithm))
        {
            result[JwksResponseParameters.Algorithm] = metadata.Algorithm;
        }

        if (!string.IsNullOrEmpty(metadata.KeyId))
        {
            result[JwksResponseParameters.KeyId] = metadata.KeyId;
        }

        if (!string.IsNullOrEmpty(metadata.X509Url))
        {
            result[JwksResponseParameters.X509Url] = metadata.X509Url;
        }

        if (metadata.X509CertificateChain?.Count > 0)
        {
            result[JwksResponseParameters.X509CertificateChain] = metadata.X509CertificateChain;
        }

        if (!string.IsNullOrEmpty(metadata.X509CertificateSha1Thumbprint))
        {
            result[JwksResponseParameters.X509CertificateSha1Thumbprint] = metadata.X509CertificateSha1Thumbprint;
        }

        if (!string.IsNullOrEmpty(metadata.X509CertificateSha256Thumbprint))
        {
            result[JwksResponseParameters.X509CertificateSha256Thumbprint] = metadata.X509CertificateSha256Thumbprint;
        }

        if (metadata.AdditionalParameters is not null)
        {
            foreach (var (key, value) in metadata.AdditionalParameters)
            {
                result[key] = value;
            }
        }

        return result;
    }

    protected class JwksResult
    {
        public JwksResult(IReadOnlyCollection<Dictionary<string, object>> keys)
        {
            Keys = keys;
        }

        [JsonPropertyName(JwksResponseParameters.Keys)]
        public IReadOnlyCollection<Dictionary<string, object>> Keys { get; }
    }
}
