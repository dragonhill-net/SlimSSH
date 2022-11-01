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
        BinaryPrimitives.WriteUInt32BigEndian(destination, value);
    }
}
