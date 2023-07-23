using System;
using System.Buffers;
using System.Security.Cryptography;

namespace OpenIdentityFramework.Services.Static.Cryptography;

public static class CryptoRandom
{
    private const int MaxStackallocBytesCount = 1024;
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    public static string Create(int bytesCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bytesCount);
        byte[]? randomBytesBufferFromPool = null;
        var randomBytesBuffer = bytesCount <= MaxStackallocBytesCount
            ? stackalloc byte[MaxStackallocBytesCount]
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
