using System;
using System.Buffers;
using System.Security.Cryptography;

namespace OpenIdentityFramework.Services.Static.Cryptography;

public static class CryptoRandom
{
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    public static string Create(int bytesCount)
    {
        const int maxStackallocBytesCount = 1024;
        if (bytesCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(bytesCount));
        }

        byte[]? randomBytesBufferFromPool = null;
        var randomBytesBuffer = bytesCount <= maxStackallocBytesCount
            ? stackalloc byte[maxStackallocBytesCount]
            : randomBytesBufferFromPool = ArrayPool<byte>.Shared.Rent(bytesCount);
        randomBytesBuffer = randomBytesBuffer[..bytesCount];
        string result;
        try
        {
            Rng.GetBytes(randomBytesBuffer);
            result = HexConverter.ToString(randomBytesBuffer);
        }
        finally
        {
            if (randomBytesBufferFromPool is not null)
            {
                ArrayPool<byte>.Shared.Return(randomBytesBufferFromPool, true);
            }
            else
            {
                randomBytesBuffer.Clear();
            }
        }

        return result;
    }
}
