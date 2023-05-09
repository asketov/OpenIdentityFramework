using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Response;
using OpenIdentityFramework.Extensions;
using OpenIdentityFramework.Services.Endpoints.Discovery.Models.DiscoveryResponseGenerator;

namespace OpenIdentityFramework.Endpoints.Results.Implementations;

public class DefaultDiscoveryDocumentResult : IEndpointHandlerResult
{
    public DefaultDiscoveryDocumentResult(OpenIdentityFrameworkOptions frameworkOptions, DiscoveryDocument discoveryDocument)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(discoveryDocument);
        FrameworkOptions = frameworkOptions;
        DiscoveryDocument = discoveryDocument;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected DiscoveryDocument DiscoveryDocument { get; }

    public virtual async Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        var response = BuildResponseParameters();
        if (FrameworkOptions.Endpoints.Discovery.ResponseHttpCacheInterval.HasValue)
        {
            httpContext.Response.SetCache(FrameworkOptions.Endpoints.Discovery.ResponseHttpCacheInterval.Value);
        }

        await httpContext.Response.WriteAsJsonAsync(response, cancellationToken);
        await httpContext.Response.Body.FlushAsync(cancellationToken);
    }

    protected virtual Dictionary<string, object> BuildResponseParameters()
    {
        var result = new Dictionary<string, object>
        {
            [DiscoveryResponseParameters.Issuer] = DiscoveryDocument.Issuer,
            [DiscoveryResponseParameters.AuthorizationEndpoint] = DiscoveryDocument.AuthorizationEndpoint,
            [DiscoveryResponseParameters.TokenEndpoint] = DiscoveryDocument.TokenEndpoint
        };
        if (!string.IsNullOrEmpty(DiscoveryDocument.UserinfoEndpoint))
        {
            result[DiscoveryResponseParameters.UserinfoEndpoint] = DiscoveryDocument.UserinfoEndpoint;
        }

        result[DiscoveryResponseParameters.JwksUri] = DiscoveryDocument.JwksUri;
        if (!string.IsNullOrEmpty(DiscoveryDocument.RegistrationEndpoint))
        {
            result[DiscoveryResponseParameters.RegistrationEndpoint] = DiscoveryDocument.RegistrationEndpoint;
        }

        if (DiscoveryDocument.ScopesSupported is not null && DiscoveryDocument.ScopesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.ScopesSupported] = DiscoveryDocument.ScopesSupported;
        }

        result[DiscoveryResponseParameters.ResponseTypesSupported] = DiscoveryDocument.ResponseTypesSupported;
        if (DiscoveryDocument.ResponseModesSupported is not null && DiscoveryDocument.ResponseModesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.ResponseModesSupported] = DiscoveryDocument.ResponseModesSupported;
        }

        if (DiscoveryDocument.GrantTypesSupported is not null && DiscoveryDocument.GrantTypesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.GrantTypesSupported] = DiscoveryDocument.GrantTypesSupported;
        }

        if (DiscoveryDocument.AcrValuesSupported is not null && DiscoveryDocument.AcrValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.AcrValuesSupported] = DiscoveryDocument.AcrValuesSupported;
        }

        result[DiscoveryResponseParameters.SubjectTypesSupported] = DiscoveryDocument.SubjectTypesSupported;
        result[DiscoveryResponseParameters.IdTokenSigningAlgValuesSupported] = DiscoveryDocument.IdTokenSigningAlgValuesSupported;
        if (DiscoveryDocument.IdTokenEncryptionAlgValuesSupported is not null && DiscoveryDocument.IdTokenEncryptionAlgValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.IdTokenEncryptionAlgValuesSupported] = DiscoveryDocument.IdTokenEncryptionAlgValuesSupported;
        }

        if (DiscoveryDocument.IdTokenEncryptionEncValuesSupported is not null && DiscoveryDocument.IdTokenEncryptionEncValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.IdTokenEncryptionEncValuesSupported] = DiscoveryDocument.IdTokenEncryptionEncValuesSupported;
        }

        if (DiscoveryDocument.UserinfoSigningAlgValuesSupported is not null && DiscoveryDocument.UserinfoSigningAlgValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.UserinfoSigningAlgValuesSupported] = DiscoveryDocument.UserinfoSigningAlgValuesSupported;
        }

        if (DiscoveryDocument.UserinfoEncryptionAlgValuesSupported is not null && DiscoveryDocument.UserinfoEncryptionAlgValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.UserinfoEncryptionAlgValuesSupported] = DiscoveryDocument.UserinfoEncryptionAlgValuesSupported;
        }

        if (DiscoveryDocument.UserinfoEncryptionEncValuesSupported is not null && DiscoveryDocument.UserinfoEncryptionEncValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.UserinfoEncryptionEncValuesSupported] = DiscoveryDocument.UserinfoEncryptionEncValuesSupported;
        }

        if (DiscoveryDocument.RequestObjectSigningAlgValuesSupported is not null && DiscoveryDocument.RequestObjectSigningAlgValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.RequestObjectSigningAlgValuesSupported] = DiscoveryDocument.RequestObjectSigningAlgValuesSupported;
        }

        if (DiscoveryDocument.RequestObjectEncryptionAlgValuesSupported is not null && DiscoveryDocument.RequestObjectEncryptionAlgValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.RequestObjectEncryptionAlgValuesSupported] = DiscoveryDocument.RequestObjectEncryptionAlgValuesSupported;
        }

        if (DiscoveryDocument.RequestObjectEncryptionEncValuesSupported is not null && DiscoveryDocument.RequestObjectEncryptionEncValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.RequestObjectEncryptionEncValuesSupported] = DiscoveryDocument.RequestObjectEncryptionEncValuesSupported;
        }

        if (DiscoveryDocument.TokenEndpointAuthMethodsSupported is not null && DiscoveryDocument.TokenEndpointAuthMethodsSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.TokenEndpointAuthMethodsSupported] = DiscoveryDocument.TokenEndpointAuthMethodsSupported;
        }

        if (DiscoveryDocument.TokenEndpointAuthSigningAlgValuesSupported is not null && DiscoveryDocument.TokenEndpointAuthSigningAlgValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.TokenEndpointAuthSigningAlgValuesSupported] = DiscoveryDocument.TokenEndpointAuthSigningAlgValuesSupported;
        }

        if (DiscoveryDocument.DisplayValuesSupported is not null && DiscoveryDocument.DisplayValuesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.DisplayValuesSupported] = DiscoveryDocument.DisplayValuesSupported;
        }

        if (DiscoveryDocument.ClaimTypesSupported is not null && DiscoveryDocument.ClaimTypesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.ClaimTypesSupported] = DiscoveryDocument.ClaimTypesSupported;
        }

        if (DiscoveryDocument.ClaimsSupported is not null && DiscoveryDocument.ClaimsSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.ClaimsSupported] = DiscoveryDocument.ClaimsSupported;
        }

        if (!string.IsNullOrEmpty(DiscoveryDocument.ServiceDocumentation))
        {
            result[DiscoveryResponseParameters.ServiceDocumentation] = DiscoveryDocument.ServiceDocumentation;
        }

        if (DiscoveryDocument.ClaimsLocalesSupported is not null && DiscoveryDocument.ClaimsLocalesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.ClaimsLocalesSupported] = DiscoveryDocument.ClaimsLocalesSupported;
        }

        if (DiscoveryDocument.UiLocalesSupported is not null && DiscoveryDocument.UiLocalesSupported.Count > 0)
        {
            result[DiscoveryResponseParameters.UiLocalesSupported] = DiscoveryDocument.UiLocalesSupported;
        }

        if (DiscoveryDocument.ClaimsParameterSupported.HasValue)
        {
            result[DiscoveryResponseParameters.ClaimsParameterSupported] = DiscoveryDocument.ClaimsParameterSupported.Value;
        }

        if (DiscoveryDocument.RequestParameterSupported.HasValue)
        {
            result[DiscoveryResponseParameters.RequestParameterSupported] = DiscoveryDocument.RequestParameterSupported.Value;
        }

        if (DiscoveryDocument.RequestUriParameterSupported.HasValue)
        {
            result[DiscoveryResponseParameters.RequestUriParameterSupported] = DiscoveryDocument.RequestUriParameterSupported.Value;
        }

        if (DiscoveryDocument.RequireRequestUriRegistration.HasValue)
        {
            result[DiscoveryResponseParameters.RequireRequestUriRegistration] = DiscoveryDocument.RequireRequestUriRegistration.Value;
        }

        if (!string.IsNullOrEmpty(DiscoveryDocument.OpPolicyUri))
        {
            result[DiscoveryResponseParameters.OpPolicyUri] = DiscoveryDocument.OpPolicyUri;
        }

        if (!string.IsNullOrEmpty(DiscoveryDocument.OpTosUri))
        {
            result[DiscoveryResponseParameters.OpTosUri] = DiscoveryDocument.OpTosUri;
        }

        if (DiscoveryDocument.AdditionalParameters != null)
        {
            foreach (var (key, value) in DiscoveryDocument.AdditionalParameters)
            {
                result[key] = value;
            }
        }

        return result;
    }
}
