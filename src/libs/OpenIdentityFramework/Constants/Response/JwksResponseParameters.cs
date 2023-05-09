namespace OpenIdentityFramework.Constants.Response;

public static class JwksResponseParameters
{
    public const string Keys = "keys";

    // https://datatracker.ietf.org/doc/html/rfc7517#section-4
    public const string KeyType = "kty";
    public const string PublicKeyUse = "use";
    public const string Algorithm = "alg";
    public const string KeyId = "kid";
    public const string X509Url = "x5u";
    public const string X509CertificateChain = "x5c";
    public const string X509CertificateSha1Thumbprint = "x5t";
    public const string X509CertificateSha256Thumbprint = "x5t#S256";
}
