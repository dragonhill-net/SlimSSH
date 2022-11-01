using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace Dragonhill.SlimSSH.Helpers;

public ref struct SshPacketDeserializer
{
    private readonly ReadOnlySpan<byte> _payloadBuffer;
    private int _readOffset;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public SshPacketDeserializer(ReadOnlySpan<byte> payloadBuffer)
    {
        _payloadBuffer = payloadBuffer;
        _readOffset = 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte ReadByte()
    {
        var value = _payloadBuffer[_readOffset];
        _readOffset += 1;
        return value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public MessageId ReadMessageId()
    {
        return (MessageId)ReadByte();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool ReadBoolean()
    {
        var value = SshPrimitives.ReadBoolean(_payloadBuffer[_readOffset]);
        ++_readOffset;
        return value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint ReadUint32()
    {
        var value = SshPrimitives.ReadUint32(_payloadBuffer.Slice(_readOffset, sizeof(uint)));
        _readOffset += sizeof(uint);
        return value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadOnlySpan<byte> ReadBytes(int length)
    {
        var span = _payloadBuffer.Slice(_readOffset, length);
        _readOffset += length;
        return span;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadOnlySpan<byte> ReadBytesString()
    {
        var length = ReadUint32();
        return ReadBytes((int)length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public NameListReader ReadNameList()
    {
        return new NameListReader(_payloadBuffer, ref _readOffset);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void CheckReadEverything()
    {
        if (_readOffset != _payloadBuffer.Length)
        {
            throw new SshException(Strings.Packet_PayloadOutOfRange);
        }
    }

    public ReadOnlySpan<byte> ReadMpintAsUnsignedBytes()
    {
        var bytes = ReadBytesString();
        return bytes[0] == 0 ? bytes[1..] : bytes;
    }

    public BigInteger ReadMpint()
    {
        var length = ReadUint32();
        return new BigInteger(ReadBytes((int)length), false, true);
    }
}
