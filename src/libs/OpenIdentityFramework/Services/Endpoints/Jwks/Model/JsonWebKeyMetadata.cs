using System.Collections.Generic;

namespace OpenIdentityFramework.Services.Endpoints.Jwks.Model;

public class JsonWebKeyMetadata
{
    /// <summary>
    ///     Json Web Key metadata.
    /// </summary>
    /// <param name="keyType">The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC".</param>
    /// <param name="publicKeyUse">The "use" (public key use) parameter identifies the intended use of the public key.</param>
    /// <param name="algorithm">The "alg" (algorithm) parameter identifies the algorithm intended for use with the key.</param>
    /// <param name="keyId">The "kid" (key ID) parameter is used to match a specific key.</param>
    /// <param name="x509Url">The "x5u" (X.509 URL) parameter is a URI that refers to a resource for an X.509 public key certificate or certificate chain.</param>
    /// <param name="x509CertificateChain">The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates.</param>
    /// <param name="x509CertificateSha1Thumbprint">The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.</param>
    /// <param name="x509CertificateSha256Thumbprint">The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.</param>
    /// <param name="additionalParameters">Any non-default parameters.</param>
    public JsonWebKeyMetadata(
        string keyType,
        string? publicKeyUse,
        string? algorithm,
        string? keyId,
        string? x509Url,
        IReadOnlyCollection<string>? x509CertificateChain,
        string? x509CertificateSha1Thumbprint,
        string? x509CertificateSha256Thumbprint,
        Dictionary<string, object>? additionalParameters)
    {
        KeyType = keyType;
        PublicKeyUse = publicKeyUse;
        Algorithm = algorithm;
        KeyId = keyId;
        X509Url = x509Url;
        X509CertificateChain = x509CertificateChain;
        X509CertificateSha1Thumbprint = x509CertificateSha1Thumbprint;
        X509CertificateSha256Thumbprint = x509CertificateSha256Thumbprint;
        AdditionalParameters = additionalParameters;
    }

    /// <summary>
    ///     The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC".
    /// </summary>
    public string KeyType { get; }

    /// <summary>
    ///     The "use" (public key use) parameter identifies the intended use of the public key.
    ///     Values defined by specification are: "sig" (signature), "enc" (encryption). Other values MAY be used.
    /// </summary>
    public string? PublicKeyUse { get; }

    /// <summary>
    ///     The "alg" (algorithm) parameter identifies the algorithm intended for use with the key.
    /// </summary>
    public string? Algorithm { get; }

    /// <summary>
    ///     The "kid" (key ID) parameter is used to match a specific key.
    /// </summary>
    public string? KeyId { get; }

    /// <summary>
    ///     The "x5u" (X.509 URL) parameter is a URI that refers to a resource for an X.509 public key certificate or certificate chain.
    /// </summary>
    public string? X509Url { get; }

    /// <summary>
    ///     The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates.
    ///     The certificate chain is represented as a JSON array of certificate value strings.
    ///     Each string in the array is a base64-encoded (Section 4 of [RFC4648] not base64url-encoded) DER PKIX certificate value.
    /// </summary>
    public IReadOnlyCollection<string>? X509CertificateChain { get; }

    /// <summary>
    ///     The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    /// </summary>
    public string? X509CertificateSha1Thumbprint { get; }

    /// <summary>
    ///     The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    /// </summary>
    public string? X509CertificateSha256Thumbprint { get; }

    /// <summary>
    ///     Any non-default parameters.
    /// </summary>
    public Dictionary<string, object>? AdditionalParameters { get; }
}
