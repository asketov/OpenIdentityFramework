using System;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Services.Static.Cryptography;

namespace OpenIdentityFramework.Services.Cryptography.Implementations;

public class DefaultIdTokenLeftMostHasher : IIdTokenLeftMostHasher
{
    public virtual string ComputeHash(string value, string tokenSigningAlgorithm)
    {
        // https://openid.net/specs/openid-financial-api-part-2-1_0.html#id-token-as-detached-signature
        switch (tokenSigningAlgorithm)
        {
            case SecurityAlgorithms.RsaSha256:
            case SecurityAlgorithms.HmacSha256:
            case SecurityAlgorithms.RsaSsaPssSha256:
            case SecurityAlgorithms.EcdsaSha256:
                {
                    Span<byte> output = stackalloc byte[Sha256Hasher.Sha256BytesCount];
                    try
                    {
                        Sha256Hasher.ComputeSha256(value, output);
                        return WebEncoders.Base64UrlEncode(output[..(Sha256Hasher.Sha256BytesCount / 2)]);
                    }
                    finally
                    {
                        output.Clear();
                    }
                }
            case SecurityAlgorithms.RsaSha384:
            case SecurityAlgorithms.HmacSha384:
            case SecurityAlgorithms.RsaSsaPssSha384:
            case SecurityAlgorithms.EcdsaSha384:
                {
                    Span<byte> output = stackalloc byte[Sha384Hasher.Sha384BytesCount];
                    try
                    {
                        Sha384Hasher.ComputeSha384(value, output);
                        return WebEncoders.Base64UrlEncode(output[..(Sha384Hasher.Sha384BytesCount / 2)]);
                    }
                    finally
                    {
                        output.Clear();
                    }
                }
            case SecurityAlgorithms.RsaSha512:
            case SecurityAlgorithms.HmacSha512:
            case SecurityAlgorithms.RsaSsaPssSha512:
            case SecurityAlgorithms.EcdsaSha512:
                {
                    Span<byte> output = stackalloc byte[Sha512Hasher.Sha512BytesCount];
                    try
                    {
                        Sha512Hasher.ComputeSha512(value, output);
                        return WebEncoders.Base64UrlEncode(output[..(Sha512Hasher.Sha512BytesCount / 2)]);
                    }
                    finally
                    {
                        output.Clear();
                    }
                }
        }

        throw new ArgumentException(
            $"Provided tokenSigningAlgorithm is not supported! Supported values are: {SecurityAlgorithms.RsaSha256}, {SecurityAlgorithms.HmacSha256}, {SecurityAlgorithms.RsaSsaPssSha256}, {SecurityAlgorithms.EcdsaSha256}, {SecurityAlgorithms.RsaSha384}, {SecurityAlgorithms.HmacSha384}, {SecurityAlgorithms.RsaSsaPssSha384}, {SecurityAlgorithms.EcdsaSha384}, {SecurityAlgorithms.RsaSha512}, {SecurityAlgorithms.HmacSha512}, {SecurityAlgorithms.RsaSsaPssSha512}, {SecurityAlgorithms.EcdsaSha512}!",
            nameof(tokenSigningAlgorithm));
    }
}
