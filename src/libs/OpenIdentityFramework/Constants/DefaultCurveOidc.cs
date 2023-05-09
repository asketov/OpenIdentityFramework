using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Constants;

[SuppressMessage("ReSharper", "IdentifierTypo")]
public static class DefaultCurveOidc
{
    // https://github.com/dotnet/runtime/blob/v7.0.5/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/ECCurve.NamedCurves.cs#L15-L17

    /// <summary>
    ///     256-bit Elliptic Curve Cryptography (ECC), also known as National Institute of Standards and Technology (NIST) P-256.
    ///     https://secg.org/sec2-v2.pdf
    ///     http://oid-info.com/get/1.2.840.10045.3.1.7
    ///     https://oidref.com/1.2.840.10045.3.1.7
    /// </summary>
    public const string EcdsaP256 = "1.2.840.10045.3.1.7";

    /// <summary>
    ///     National Institute of Standards and Technology (NIST) 384-bit elliptic curve.
    ///     https://secg.org/sec2-v2.pdf
    ///     http://oid-info.com/get/1.3.132.0.34
    ///     https://oidref.com/1.3.132.0.34
    /// </summary>
    public const string EcdsaP384 = "1.3.132.0.34";

    /// <summary>
    ///     National Institute of Standards and Technology (NIST) 512-bit elliptic curve
    ///     https://secg.org/sec2-v2.pdf
    ///     http://oid-info.com/get/1.3.132.0.35
    ///     https://oidref.com/1.3.132.0.35
    /// </summary>
    public const string EcdsaP521 = "1.3.132.0.35";
}
