using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace OpenIdentityFramework.Services.Static.Cryptography;

// based on https://github.com/dotnet/aspnetcore/blob/v7.0.5/src/Identity/Extensions.Core/src/PasswordHasher.cs
public static class Pbkdf2Hasher
{
    private const int MaxSaltStackallocSize = 256;
    private const int MaxDeriveKeyStackallocSize = 512;
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    [SuppressMessage("ReSharper", "RedundantCast")]
    public static byte[] ComputeHash(
        ReadOnlySpan<byte> input,
        KeyDerivationPrf prf,
        int iterations,
        int saltLength,
        int deriveKeyLength)
    {
        var algorithmName = prf switch
        {
            KeyDerivationPrf.HMACSHA1 => HashAlgorithmName.SHA1,
            KeyDerivationPrf.HMACSHA256 => HashAlgorithmName.SHA256,
            KeyDerivationPrf.HMACSHA512 => HashAlgorithmName.SHA512,
            _ => throw new ArgumentOutOfRangeException(nameof(prf))
        };

        byte[]? saltFromPool = null;
        var salt = saltLength <= MaxSaltStackallocSize
            ? stackalloc byte[MaxSaltStackallocSize]
            : saltFromPool = ArrayPool<byte>.Shared.Rent(saltLength);
        salt = salt[..saltLength];
        try
        {
            byte[]? deriveKeyFromPool = null;
            var deriveKey = deriveKeyLength <= MaxDeriveKeyStackallocSize
                ? stackalloc byte[MaxDeriveKeyStackallocSize]
                : deriveKeyFromPool = ArrayPool<byte>.Shared.Rent(deriveKeyLength);
            deriveKey = deriveKey[..deriveKeyLength];
            try
            {
                Rng.GetBytes(salt);
                // https://github.com/dotnet/aspnetcore/blob/v7.0.5/src/DataProtection/Cryptography.KeyDerivation/src/PBKDF2/NetCorePbkdf2Provider.cs#L40
                Rfc2898DeriveBytes.Pbkdf2(input, salt, deriveKey, iterations, algorithmName);
                var result = new byte[13 + saltLength + deriveKeyLength];
                var output = result.AsSpan();
                output[0] = 0x01;
                WriteNetworkByteOrder(output, 1, (uint) prf);
                WriteNetworkByteOrder(output, 5, (uint) iterations);
                WriteNetworkByteOrder(output, 9, (uint) saltLength);
                salt.CopyTo(output.Slice(13, saltLength));
                deriveKey.CopyTo(output[(13 + saltLength)..]);
                return result;
            }
            finally
            {
                if (deriveKeyFromPool is not null)
                {
                    ArrayPool<byte>.Shared.Return(deriveKeyFromPool, true);
                }
                else
                {
                    deriveKey.Clear();
                }
            }
        }
        finally
        {
            if (saltFromPool is not null)
            {
                ArrayPool<byte>.Shared.Return(saltFromPool, true);
            }
            else
            {
                salt.Clear();
            }
        }

        static void WriteNetworkByteOrder(Span<byte> buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte) (value >> 24);
            buffer[offset + 1] = (byte) (value >> 16);
            buffer[offset + 2] = (byte) (value >> 8);
            buffer[offset + 3] = (byte) (value >> 0);
        }
    }

    [SuppressMessage("ReSharper", "RedundantCast")]
    public static bool IsValid(ReadOnlySpan<byte> input, ReadOnlySpan<byte> hash)
    {
        try
        {
            if (hash.Length < 13) // header is 13 bytes
            {
                return false;
            }

            if (hash[0] != 0x01) // format marker
            {
                return false;
            }

            // Read and validate header information
            var prf = (KeyDerivationPrf) ReadNetworkByteOrder(hash, 1);
            HashAlgorithmName algorithmName;
            switch (prf)
            {
                case KeyDerivationPrf.HMACSHA1:
                    algorithmName = HashAlgorithmName.SHA1;
                    break;
                case KeyDerivationPrf.HMACSHA256:
                    algorithmName = HashAlgorithmName.SHA256;
                    break;
                case KeyDerivationPrf.HMACSHA512:
                    algorithmName = HashAlgorithmName.SHA512;
                    break;
                default:
                    return false;
            }

            var iterations = (int) ReadNetworkByteOrder(hash, 5);
            if (iterations is < 1000 or > 1_000_000_000)
            {
                return false;
            }

            var saltLength = (int) ReadNetworkByteOrder(hash, 9);
            if (saltLength < 8)
            {
                return false;
            }

            var deriveKeyLength = hash.Length - 13 - saltLength;
            if (deriveKeyLength < 8)
            {
                return false;
            }

            byte[]? saltFromPool = null;
            var salt = saltLength <= MaxSaltStackallocSize
                ? stackalloc byte[MaxSaltStackallocSize]
                : saltFromPool = ArrayPool<byte>.Shared.Rent(saltLength);
            salt = salt[..saltLength];
            try
            {
                hash.Slice(13, saltLength).CopyTo(salt);
                byte[]? expectedDeriveKeyFromPool = null;
                var expectedDeriveKey = deriveKeyLength <= MaxDeriveKeyStackallocSize
                    ? stackalloc byte[MaxDeriveKeyStackallocSize]
                    : expectedDeriveKeyFromPool = ArrayPool<byte>.Shared.Rent(deriveKeyLength);
                expectedDeriveKey = expectedDeriveKey[..deriveKeyLength];
                try
                {
                    hash[(13 + saltLength)..].CopyTo(expectedDeriveKey);
                    byte[]? actualDeriveKeyFromPool = null;
                    var actualDeriveKey = deriveKeyLength <= MaxDeriveKeyStackallocSize
                        ? stackalloc byte[MaxDeriveKeyStackallocSize]
                        : actualDeriveKeyFromPool = ArrayPool<byte>.Shared.Rent(deriveKeyLength);
                    actualDeriveKey = actualDeriveKey[..deriveKeyLength];
                    try
                    {
                        // https://github.com/dotnet/aspnetcore/blob/v7.0.5/src/DataProtection/Cryptography.KeyDerivation/src/PBKDF2/NetCorePbkdf2Provider.cs#L40
                        Rfc2898DeriveBytes.Pbkdf2(input, salt, actualDeriveKey, iterations, algorithmName);
                        return CryptographicOperations.FixedTimeEquals(expectedDeriveKey, actualDeriveKey);
                    }
                    finally
                    {
                        if (actualDeriveKeyFromPool is not null)
                        {
                            ArrayPool<byte>.Shared.Return(actualDeriveKeyFromPool, true);
                        }
                        else
                        {
                            actualDeriveKey.Clear();
                        }
                    }
                }
                finally
                {
                    if (expectedDeriveKeyFromPool is not null)
                    {
                        ArrayPool<byte>.Shared.Return(expectedDeriveKeyFromPool, true);
                    }
                    else
                    {
                        expectedDeriveKey.Clear();
                    }
                }
            }
            finally
            {
                if (saltFromPool is not null)
                {
                    ArrayPool<byte>.Shared.Return(saltFromPool, true);
                }
                else
                {
                    salt.Clear();
                }
            }
        }
#pragma warning disable CA1031
        catch
#pragma warning restore CA1031
        {
            return false;
        }

        static uint ReadNetworkByteOrder(ReadOnlySpan<byte> buffer, int offset)
        {
            return ((uint) buffer[offset + 0] << 24)
                   | ((uint) buffer[offset + 1] << 16)
                   | ((uint) buffer[offset + 2] << 8)
                   | (uint) buffer[offset + 3];
        }
    }
}
