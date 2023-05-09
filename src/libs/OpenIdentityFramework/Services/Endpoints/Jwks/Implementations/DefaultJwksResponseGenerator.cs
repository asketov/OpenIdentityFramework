using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Jwks.Model;
using OpenIdentityFramework.Services.Static.Cryptography;

namespace OpenIdentityFramework.Services.Endpoints.Jwks.Implementations;

public class DefaultJwksResponseGenerator<TRequestContext>
    : IJwksResponseGenerator<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    public DefaultJwksResponseGenerator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IMemoryCache cache,
        IKeyMaterialService<TRequestContext> keyMaterialService)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(keyMaterialService);
        FrameworkOptions = frameworkOptions;
        Cache = cache;
        KeyMaterialService = keyMaterialService;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IMemoryCache Cache { get; }
    protected IKeyMaterialService<TRequestContext> KeyMaterialService { get; }

    public virtual async Task<JwkSetMetadata> CreateJwkSetAsync(
        TRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        const string cacheKey = "OpenIdentityFramework_Oidc_JwksDocument";

        cancellationToken.ThrowIfCancellationRequested();
        if (FrameworkOptions.Endpoints.Jwks.JwksDocumentInMemoryCacheInterval.HasValue
            && FrameworkOptions.Endpoints.Jwks.JwksDocumentInMemoryCacheInterval.Value > TimeSpan.Zero)
        {
            if (Cache.TryGetValue<JwkSetMetadata>(cacheKey, out var cachedDocument) && cachedDocument is not null)
            {
                return cachedDocument;
            }

            var discoveryDoc = await BuildJwkSetAsync(requestContext, cancellationToken);
            Cache.Set(cacheKey, discoveryDoc, FrameworkOptions.Endpoints.Jwks.JwksDocumentInMemoryCacheInterval.Value);
            return discoveryDoc;
        }
        else
        {
            var discoveryDoc = await BuildJwkSetAsync(requestContext, cancellationToken);
            return discoveryDoc;
        }
    }

    protected virtual async Task<JwkSetMetadata> BuildJwkSetAsync(
        TRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var jwks = new List<JsonWebKeyMetadata>();
        var allKeys = await KeyMaterialService.GetAllAsync(requestContext, cancellationToken);
        foreach (var key in allKeys)
        {
            var securityKey = key.Key;
            var algorithm = key.Algorithm;
            if (securityKey is X509SecurityKey x509Key && TryGetJwkFromX509SecurityKey(x509Key, algorithm, out var x509KeyJwk))
            {
                jwks.Add(x509KeyJwk);
            }
            else if (securityKey is RsaSecurityKey rsaKey && TryGetJwkFromRsaSecurityKey(rsaKey, algorithm, out var rsaKeyJwk))
            {
                jwks.Add(rsaKeyJwk);
            }
            else if (securityKey is ECDsaSecurityKey ecdsaKey && TryGetJwkFromEcDsaSecurityKey(ecdsaKey, algorithm, out var ecdsaKeyJwk))
            {
                jwks.Add(ecdsaKeyJwk);
            }
            else if (securityKey is JsonWebKey jsonWebKey && TryGetJwkFromJsonWebKey(jsonWebKey, algorithm, out var jsonWebJwk))
            {
                jwks.Add(jsonWebJwk);
            }
        }

        return new(jwks);
    }

    protected virtual bool TryGetJwkFromX509SecurityKey(X509SecurityKey x509Key, string algorithm, [NotNullWhen(true)] out JsonWebKeyMetadata? result)
    {
        ArgumentNullException.ThrowIfNull(x509Key);
        ArgumentNullException.ThrowIfNull(algorithm);
        var keyId = x509Key.KeyId;
        var certBase64 = Convert.ToBase64String(x509Key.Certificate.RawData);
        var thumbprint = WebEncoders.Base64UrlEncode(x509Key.Certificate.GetCertHash());
        if (x509Key.PublicKey is RSA rsa)
        {
            var parameters = rsa.ExportParameters(false);
            if (parameters.Exponent is not null && parameters.Modulus is not null)
            {
                var exponent = WebEncoders.Base64UrlEncode(parameters.Exponent);
                var modulus = WebEncoders.Base64UrlEncode(parameters.Modulus);

                var rsaJsonWebKey = new JsonWebKeyMetadata(
                    "RSA",
                    "sig",
                    algorithm,
                    keyId,
                    null,
                    new HashSet<string>
                    {
                        certBase64
                    },
                    thumbprint,
                    null,
                    new()
                    {
                        { "e", exponent },
                        { "n", modulus }
                    });
                result = rsaJsonWebKey;
                return true;
            }
        }
        else if (x509Key.PublicKey is ECDsa ecdsa)
        {
            var parameters = ecdsa.ExportParameters(false);
            if (parameters.Q.X is not null && parameters.Q.Y is not null && CryptoHelper.TryGetCrvValueFromCurve(parameters.Curve, out var crv))
            {
                var x = WebEncoders.Base64UrlEncode(parameters.Q.X);
                var y = WebEncoders.Base64UrlEncode(parameters.Q.Y);
                var ecdsaJsonWebKey = new JsonWebKeyMetadata(
                    "EC", //kty
                    "sig", //use
                    algorithm, //alg
                    keyId, //kid
                    null, //x5u
                    new HashSet<string> // "x5c"
                    {
                        certBase64
                    },
                    thumbprint, // x5t
                    null, //x5t#S256
                    new()
                    {
                        { "x", x },
                        { "y", y },
                        { "crv", crv }
                    });
                result = ecdsaJsonWebKey;
                return true;
            }
        }

        result = null;
        return false;
    }

    protected virtual bool TryGetJwkFromRsaSecurityKey(RsaSecurityKey rsaKey, string algorithm, [NotNullWhen(true)] out JsonWebKeyMetadata? result)
    {
        ArgumentNullException.ThrowIfNull(rsaKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        var parameters = rsaKey.Rsa?.ExportParameters(false) ?? rsaKey.Parameters;
        if (parameters.Exponent is not null && parameters.Modulus is not null)
        {
            var keyId = rsaKey.KeyId;
            var exponent = WebEncoders.Base64UrlEncode(parameters.Exponent);
            var modulus = WebEncoders.Base64UrlEncode(parameters.Modulus);
            var rsaJsonWebKey = new JsonWebKeyMetadata(
                "RSA", //kty
                "sig", //use
                algorithm, //alg
                keyId, //kid
                null, //x5u
                null, // "x5c"
                null, // x5t
                null, //x5t#S256
                new()
                {
                    { "e", exponent },
                    { "n", modulus }
                });
            result = rsaJsonWebKey;
            return true;
        }

        result = null;
        return false;
    }

    protected virtual bool TryGetJwkFromEcDsaSecurityKey(ECDsaSecurityKey ecdsaKey, string algorithm, [NotNullWhen(true)] out JsonWebKeyMetadata? result)
    {
        ArgumentNullException.ThrowIfNull(ecdsaKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        var parameters = ecdsaKey.ECDsa.ExportParameters(false);
        if (parameters.Q.X is not null && parameters.Q.Y is not null && CryptoHelper.TryGetCrvValueFromCurve(parameters.Curve, out var crv))
        {
            var x = WebEncoders.Base64UrlEncode(parameters.Q.X);
            var y = WebEncoders.Base64UrlEncode(parameters.Q.Y);
            var ecdsaJsonWebKey = new JsonWebKeyMetadata(
                "EC", //kty
                "sig", //use
                algorithm, //alg
                ecdsaKey.KeyId, //kid
                null, //x5u
                null, // "x5c"
                null, // x5t
                null, //x5t#S256
                new()
                {
                    { "x", x },
                    { "y", y },
                    { "crv", crv }
                });
            result = ecdsaJsonWebKey;
            return true;
        }


        result = null;
        return false;
    }

    protected virtual bool TryGetJwkFromJsonWebKey(JsonWebKey jsonWebKey, string algorithm, [NotNullWhen(true)] out JsonWebKeyMetadata? result)
    {
        ArgumentNullException.ThrowIfNull(jsonWebKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        if (string.IsNullOrEmpty(jsonWebKey.Use) || jsonWebKey.Use != "sig")
        {
            result = null;
            return false;
        }

        IReadOnlyCollection<string>? x509CertificateChain = jsonWebKey.X5c?.Count > 0
            ? new List<string>(jsonWebKey.X5c)
            : null;

        var additionalParameters = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(jsonWebKey.E))
        {
            additionalParameters["e"] = jsonWebKey.E;
        }

        if (!string.IsNullOrEmpty(jsonWebKey.N))
        {
            additionalParameters["n"] = jsonWebKey.N;
        }

        if (!string.IsNullOrEmpty(jsonWebKey.Crv))
        {
            additionalParameters["crv"] = jsonWebKey.Crv;
        }

        if (!string.IsNullOrEmpty(jsonWebKey.X))
        {
            additionalParameters["x"] = jsonWebKey.X;
        }

        if (!string.IsNullOrEmpty(jsonWebKey.Y))
        {
            additionalParameters["y"] = jsonWebKey.Y;
        }

        var jwkJsonWebKey = new JsonWebKeyMetadata(
            jsonWebKey.Kty,
            jsonWebKey.Use,
            jsonWebKey.Alg,
            jsonWebKey.KeyId,
            jsonWebKey.X5u,
            x509CertificateChain,
            jsonWebKey.X5t,
            jsonWebKey.X5tS256,
            additionalParameters
        );
        result = jwkJsonWebKey;
        return true;
    }
}
