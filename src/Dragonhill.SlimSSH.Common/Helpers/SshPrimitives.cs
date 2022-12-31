using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace Dragonhill.SlimSSH.Helpers;

public static class SshPrimitives
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ReadBoolean(byte source)
    {
        return source != 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint ReadUint32(ReadOnlySpan<byte> source)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(source);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong ReadUint64(ReadOnlySpan<byte> source)
    {
        return BinaryPrimitives.ReadUInt64BigEndian(source);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteUint32(Span<byte> destination, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination, value);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteUint64(Span<byte> destination, uint value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination, value);
    }

    public static int WriteUnsignedAsMPint(ReadOnlySpan<byte> input, Span<byte> mpint)
    {
        var leadingZeros = 0;

        while (leadingZeros < input.Length && input[leadingZeros] == 0)
        {
            ++leadingZeros;
        }

        if (leadingZeros == input.Length)
        {
            WriteUint32(mpint, 0);
            return sizeof(uint);
        }

        var bytesWithoutLeadingZeros = input[leadingZeros..];

        int offset;
        if((bytesWithoutLeadingZeros[0] & 0x80) != 0)
        {
            WriteUint32(mpint, (uint)(bytesWithoutLeadingZeros.Length + 1));
            mpint[4] = 0;
            offset = 5;
        }
        else
        {
            WriteUint32(mpint, (uint)bytesWithoutLeadingZeros.Length);
            offset = 4;
        }

        bytesWithoutLeadingZeros.CopyTo(mpint[offset..]);

        return offset + bytesWithoutLeadingZeros.Length;
    }
}
