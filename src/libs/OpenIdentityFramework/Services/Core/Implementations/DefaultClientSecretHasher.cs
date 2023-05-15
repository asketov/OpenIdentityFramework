using System.Buffers;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using OpenIdentityFramework.Services.Static.Cryptography;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultClientSecretHasher : IClientSecretHasher
{
    protected const int IterationsCount = 10_000;

    public static readonly IClientSecretHasher Instance = new DefaultClientSecretHasher();

    public virtual byte[] ComputeHash(string rawClientSecret)
    {
        const int maxStackallocBytesCount = 1024;
        var src = !string.IsNullOrEmpty(rawClientSecret) ? rawClientSecret : string.Empty;
        var bufferSize = Encoding.UTF8.GetMaxByteCount(src.Length);
        byte[]? bufferFromPool = null;
        var buffer = bufferSize <= maxStackallocBytesCount
            ? stackalloc byte[maxStackallocBytesCount]
            : bufferFromPool = ArrayPool<byte>.Shared.Rent(bufferSize);
        buffer = buffer[..bufferSize];
        try
        {
            var bytesCount = Encoding.UTF8.GetBytes(src, buffer);
            return Pbkdf2Hasher.ComputeHash(buffer[..bytesCount], KeyDerivationPrf.HMACSHA256, IterationsCount, 16, 32);
        }
        finally
        {
            if (bufferFromPool is not null)
            {
                ArrayPool<byte>.Shared.Return(bufferFromPool, true);
            }
            else
            {
                buffer.Clear();
            }
        }
    }

    public virtual bool IsValid(string rawClientSecret, byte[] clientSecretHash)
    {
        const int maxStackallocBytesCount = 1024;
        var src = !string.IsNullOrEmpty(rawClientSecret) ? rawClientSecret : string.Empty;
        var bufferSize = Encoding.UTF8.GetMaxByteCount(src.Length);
        byte[]? bufferFromPool = null;
        var buffer = bufferSize <= maxStackallocBytesCount
            ? stackalloc byte[maxStackallocBytesCount]
            : bufferFromPool = ArrayPool<byte>.Shared.Rent(bufferSize);
        buffer = buffer[..bufferSize];
        try
        {
            var bytesCount = Encoding.UTF8.GetBytes(src, buffer);
            return Pbkdf2Hasher.IsValid(buffer[..bytesCount], clientSecretHash);
        }
        finally
        {
            if (bufferFromPool is not null)
            {
                ArrayPool<byte>.Shared.Return(bufferFromPool, true);
            }
            else
            {
                buffer.Clear();
            }
        }
    }
}
