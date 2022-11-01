using Dragonhill.SlimSSH.Protocol;
using System.Security.Cryptography;

namespace Dragonhill.SlimSSH.Helpers;

public readonly struct SshUnfinishedPacket
{
    private readonly byte[] _buffer;
    private readonly int _lengthWithOffsetWithoutPadding;

    public int Offset { get; }


    public SshUnfinishedPacket(byte[] buffer, int offset, int lengthWithOffsetWithoutPadding)
    {
        Offset = offset;
        _buffer = buffer;
        _lengthWithOffsetWithoutPadding = lengthWithOffsetWithoutPadding;
    }

    internal Memory<byte> FinishPacket(int effectivePaddingSize)
    {
        var packetBytesWithoutPadding = _lengthWithOffsetWithoutPadding - Offset;

        var paddingAmount = effectivePaddingSize - packetBytesWithoutPadding % effectivePaddingSize;

        if (paddingAmount < 4)
        {
            paddingAmount += effectivePaddingSize;
        }

        var packetLength = (uint)(packetBytesWithoutPadding - sizeof(uint) + paddingAmount);

        SshPrimitives.WriteUint32(_buffer.AsSpan(Offset + PacketConstants.PacketLengthOffset), packetLength);
        _buffer[Offset + PacketConstants.PaddingOffset] = (byte)paddingAmount;

        RandomNumberGenerator.Fill(_buffer.AsSpan(_lengthWithOffsetWithoutPadding, paddingAmount));

        return _buffer.AsMemory(0, _lengthWithOffsetWithoutPadding + paddingAmount);
    }
}
