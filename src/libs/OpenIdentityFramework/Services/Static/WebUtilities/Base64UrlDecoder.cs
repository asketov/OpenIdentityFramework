using System;
using System.Buffers;

namespace OpenIdentityFramework.Services.Static.WebUtilities;

public static class Base64UrlDecoder
{
    public static int ComputeRequiredBufferSize(int inputLength)
    {
        return ((inputLength >> 2) * 3) + 2;
    }

    public static bool TryDecode(ReadOnlySpan<char> chars, Span<byte> bytes, out int bytesWritten)
    {
        const int maxStackallocCharsCount = 512;
        var mod = chars.Length % 4;
        if (mod == 1)
        {
            bytesWritten = 0;
            return false;
        }

        var needReplace = chars.IndexOfAny('-', '_') >= 0;
        var decodedLength = chars.Length + ((4 - mod) % 4);

        if (!needReplace && decodedLength == chars.Length)
        {
            return Convert.TryFromBase64Chars(chars, bytes, out bytesWritten);
        }

        char[]? base64CharsBufferFromPool = null;
        var buffer = decodedLength <= maxStackallocCharsCount
            ? stackalloc char[maxStackallocCharsCount]
            : base64CharsBufferFromPool = ArrayPool<char>.Shared.Rent(decodedLength);
        buffer = buffer[..decodedLength];
        try
        {
            chars.CopyTo(buffer);
            if (chars.Length < buffer.Length)
            {
                buffer[chars.Length] = '=';
                if (chars.Length + 1 < buffer.Length)
                {
                    buffer[chars.Length + 1] = '=';
                }
            }

            if (needReplace)
            {
                var remaining = buffer;
                int pos;
                while ((pos = remaining.IndexOfAny('-', '_')) >= 0)
                {
                    remaining[pos] = remaining[pos] == '-' ? '+' : '/';
                    remaining = remaining[(pos + 1)..];
                }
            }

            return Convert.TryFromBase64Chars(buffer, bytes, out bytesWritten);
        }
        finally
        {
            if (base64CharsBufferFromPool is not null)
            {
                ArrayPool<char>.Shared.Return(base64CharsBufferFromPool, true);
            }
            else
            {
                buffer.Clear();
            }
        }
    }
}
