using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.IO;
using Dragonhill.SlimSSH.Protocol;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Dragonhill.SlimSSH.Helpers;

public struct SshPacketBuilder : IDisposable
{
    private readonly byte[] _buffer;
    private readonly int _start;
    private int _writeOffset;

    internal SshPacketBuilder(ISshPacketWriter writer, int maxPayloadSize = Constants.RequiredSupportedPayloadSize)
    {
        _buffer = ArrayPool<byte>.Shared.Rent(maxPayloadSize + writer.RequiredBytesInFrontOfBuffer + writer.MaxPaddingSize + PacketConstants.PayloadOffset);
        _start = writer.RequiredBytesInFrontOfBuffer;
        _writeOffset = _start + PacketConstants.PayloadOffset;
    }

    public SshPacketBuilder(int payloadSize)
    {
        _buffer = ArrayPool<byte>.Shared.Rent(payloadSize + PacketConstants.PayloadOffset);
        _start = 0;
        _writeOffset = PacketConstants.PayloadOffset;
    }

    public SshUnfinishedPacket GetUnfinishedPacket() => new(_buffer, _start, _writeOffset);

    public ReadOnlySpan<byte> GetPayloadSpan()
    {
        return _buffer.AsSpan(_start + PacketConstants.PayloadOffset, _writeOffset - _start - PacketConstants.PayloadOffset);
    }

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(_buffer);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteBoolean(bool value)
    {
        _buffer[_writeOffset] = value ? (byte)1 : (byte)0;
        ++_writeOffset;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteMessageId(MessageId value)
    {
        _buffer[_writeOffset] = (byte)value;
        ++_writeOffset;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteByte(byte value)
    {
        _buffer[_writeOffset] = value;
        ++_writeOffset;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteBytes(ReadOnlySpan<byte> bytes)
    {
        bytes.CopyTo(_buffer.AsSpan(_writeOffset));
        _writeOffset += bytes.Length;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteBytesString(ReadOnlySpan<byte> bytes)
    {
        WriteUint32((uint)bytes.Length);
        WriteBytes(bytes);
    }

    public void WriteUnsignedAsMPint(ReadOnlySpan<byte> bytes)
    {
        var leadingZeros = 0;

        while (leadingZeros < bytes.Length && bytes[leadingZeros] == 0)
        {
            ++leadingZeros;
        }

        var bytesWithoutLeadingZeros = bytes[leadingZeros..];

        if ((bytesWithoutLeadingZeros[0] & 0x80) != 0)
        {
            WriteUint32((uint)(bytesWithoutLeadingZeros.Length + 1));
            WriteByte(0);
        }
        else
        {
            WriteUint32((uint)(bytesWithoutLeadingZeros.Length));
        }
        WriteBytes(bytesWithoutLeadingZeros);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteUint32(uint value)
    {
        SshPrimitives.WriteUint32(_buffer.AsSpan(_writeOffset, sizeof(uint)), value);
        _writeOffset += sizeof(uint);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteCryptoRandomBytes(int length)
    {
        RandomNumberGenerator.Fill(_buffer.AsSpan(_writeOffset, length));
        _writeOffset += length;
    }

    public void WriteString(string str)
    {
        var length = Encoding.UTF8.GetByteCount(str);
        WriteUint32((uint)length);
        Encoding.UTF8.GetBytes(str, _buffer.AsSpan(_writeOffset, length));
        _writeOffset += length;
    }

    public void WriteNameList(IReadOnlyList<IAlgorithmId> algorithms)
    {
        var lengthSpan = _buffer.AsSpan(_writeOffset, sizeof(uint));
        _writeOffset += sizeof(uint);

        uint length = 0;

        if (algorithms.Count > 0)
        {
            for (var i = 0; i < algorithms.Count; i++)
            {
                var idBytes = algorithms[i].IdBytes;

                if (i != 0)
                {
                    _buffer[_writeOffset] = (byte)',';
                    ++_writeOffset;
                    ++length;
                }

                idBytes.CopyTo(_buffer.AsSpan(_writeOffset, idBytes.Length));
                _writeOffset += idBytes.Length;
                length += (uint)idBytes.Length;
            }
        }

        SshPrimitives.WriteUint32(lengthSpan, length);
    }

    public void WriteNoneNameList()
    {
        var target = _buffer.AsSpan(_writeOffset, 8);
        SshPrimitives.WriteUint32(target, 4);
        target[4] = (byte)'n';
        target[5] = (byte)'o';
        target[6] = (byte)'n';
        target[7] = (byte)'e';
        _writeOffset += target.Length;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteEmptyNameList()
    {
        WriteUint32(0);
    }
}
