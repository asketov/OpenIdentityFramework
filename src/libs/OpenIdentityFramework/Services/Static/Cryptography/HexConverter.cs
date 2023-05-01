using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace OpenIdentityFramework.Services.Static.Cryptography;

public static class HexConverter
{
    public static string ToString(ReadOnlySpan<byte> bytes)
    {
        const int maxStackallocCharsCount = 512;
        if (bytes.Length == 0)
        {
            return string.Empty;
        }

        var charsCount = bytes.Length * 2;

        char[]? hexCharsBufferFromPool = null;
        var hexCharsBuffer = charsCount <= maxStackallocCharsCount
            ? stackalloc char[maxStackallocCharsCount]
            : hexCharsBufferFromPool = ArrayPool<char>.Shared.Rent(charsCount);
        hexCharsBuffer = hexCharsBuffer[..charsCount];
        string result;
        try
        {
            for (var i = 0; i < bytes.Length; i++)
            {
                ToCharsBuffer(bytes[i], hexCharsBuffer, i * 2);
            }

            result = new(hexCharsBuffer);
        }
        finally
        {
            if (hexCharsBufferFromPool is not null)
            {
                ArrayPool<char>.Shared.Return(hexCharsBufferFromPool, true);
            }
            else
            {
                hexCharsBuffer.Clear();
            }
        }

        return result;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [SuppressMessage("ReSharper", "RedundantCast")]
    [SuppressMessage("ReSharper", "SuggestVarOrType_BuiltInTypes")]
    [SuppressMessage("Style", "IDE0007:Use implicit type")]
    private static void ToCharsBuffer(byte value, Span<char> buffer, int startingIndex = 0)
    {
        uint difference = (((uint) value & 0xF0U) << 4) + ((uint) value & 0x0FU) - 0x8989U;
        uint packedResult = ((((uint) -(int) difference & 0x7070U) >> 4) + difference + 0xB9B9U) | (uint) 0x2020U;

        buffer[startingIndex + 1] = (char) (packedResult & 0xFF);
        buffer[startingIndex] = (char) (packedResult >> 8);
    }
}
