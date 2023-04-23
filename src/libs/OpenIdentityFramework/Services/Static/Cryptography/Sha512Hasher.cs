using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace OpenIdentityFramework.Services.Static.Cryptography;

public static class Sha512Hasher
{
    public const int Sha512BytesCount = 512 / 8;

    public static void ComputeSha512(ReadOnlySpan<char> rawValue, Span<byte> output)
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
            SHA512.HashData(bytesBuffer[..bytesCount], output);
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
