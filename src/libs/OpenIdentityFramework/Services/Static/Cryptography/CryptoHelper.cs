using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Services.Static.Cryptography;

public static class CryptoHelper
{
    /// <summary>
    ///     Converts OIDC to https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1 "crv" parameter if possible.
    /// </summary>
    /// <param name="curve">An elliptic curve.</param>
    /// <param name="value">Valid RFC7518 "crv" parameter when method returns <see langword="true" />; otherwise <see langword="null" />.</param>
    /// <returns></returns>
    public static bool TryGetCrvValueFromCurve(ECCurve curve, [NotNullWhen(true)] out string? value)
    {
        if (curve.Oid.Value is not null)
        {
            switch (curve.Oid.Value)
            {
                case DefaultCurveOidc.EcdsaP256:
                    value = JsonWebKeyECTypes.P256;
                    return true;
                case DefaultCurveOidc.EcdsaP384:
                    value = JsonWebKeyECTypes.P384;
                    return true;
                case DefaultCurveOidc.EcdsaP521:
                    value = JsonWebKeyECTypes.P521;
                    return true;
            }
        }

        value = null;
        return false;
    }
}
