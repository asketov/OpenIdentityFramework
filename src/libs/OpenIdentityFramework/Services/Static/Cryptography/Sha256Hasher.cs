using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace OpenIdentityFramework.Services.Static.Cryptography;

public static class Sha256Hasher
{
    public const int Sha256BytesCount = 256 / 8;

    public static void ComputeSha256(ReadOnlySpan<char> rawValue, Span<byte> output)
    {
        const int maxStackallocBytesCount = 1024;
        var bufferSize = Encoding.ASCII.GetMaxByteCount(rawValue.Length);
        byte[]? bufferFromPool = null;
        var bytesBuffer = bufferSize <= maxStackallocBytesCount
            ? stackalloc byte[maxStackallocBytesCount]
            : bufferFromPool = ArrayPool<byte>.Shared.Rent(bufferSize);
        bytesBuffer = bytesBuffer[..bufferSize];
        try
        {
            var bytesCount = Encoding.ASCII.GetBytes(rawValue, bytesBuffer);
            SHA256.HashData(bytesBuffer[..bytesCount], output);
        }
        finally
        {
            if (bufferFromPool is not null)
            {
                ArrayPool<byte>.Shared.Return(bufferFromPool, true);
            }
            else
            {
                bytesBuffer.Clear();
            }
        }
    }
}
