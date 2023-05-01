using System;
using System.Security.Cryptography;
using OpenIdentityFramework.Constants.Request.Authorize;
using OpenIdentityFramework.Services.Static.Cryptography;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations;

public class DefaultCodeVerifierValidator : ICodeVerifierValidator
{
    public bool IsValid(string codeChallenge, string codeChallengeMethod, string codeVerifier)
    {
        if (codeChallengeMethod == CodeChallengeMethod.Plain)
        {
            return IsPlainValid(codeChallenge, codeVerifier);
        }

        if (codeChallengeMethod == CodeChallengeMethod.S256)
        {
            return IsS256Valid(codeChallenge, codeVerifier);
        }

        return false;
    }

    private static bool IsPlainValid(string? codeChallenge, string? codeVerifier)
    {
        return !string.IsNullOrEmpty(codeChallenge)
               && !string.IsNullOrEmpty(codeVerifier)
               && string.Equals(codeChallenge, codeVerifier, StringComparison.Ordinal);
    }

    private static bool IsS256Valid(string? codeChallenge, string? codeVerifier)
    {
        if (string.IsNullOrEmpty(codeChallenge) || string.IsNullOrEmpty(codeVerifier))
        {
            return false;
        }

        if (!HexValidator.IsValid(codeChallenge))
        {
            return false;
        }

        Span<byte> codeVerifierHash = stackalloc byte[Sha256Hasher.Sha256BytesCount];
        Sha256Hasher.ComputeSha256(codeVerifier, codeVerifierHash);
        var codeChallengeBytes = Convert.FromHexString(codeChallenge);
        return CryptographicOperations.FixedTimeEquals(codeVerifierHash, codeChallengeBytes);
    }
}
