using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Protocol;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Dragonhill.SlimSSH.Helpers;

public ref struct SshSerializer
{
    private Span<byte> _buffer;
    private int _writeOffset;

    private readonly ref SshPacketPlaintextBuffer _plaintextBuffer;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public SshSerializer(Span<byte> buffer)
    {
        _buffer = buffer;
        _writeOffset = 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public SshSerializer(ref SshPacketPlaintextBuffer plaintextBuffer)
    {
        _plaintextBuffer = ref plaintextBuffer;
        _buffer = plaintextBuffer.GetWritablePayloadAndPaddingSpan();
        _writeOffset = 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadOnlySpan<byte> Finish()
    {
        if (!Unsafe.IsNullRef(ref _plaintextBuffer))
        {
            _plaintextBuffer.FinishWritingPayload(_writeOffset);
        }


        var writtenSpan = _buffer[.._writeOffset];
        _buffer = Span<byte>.Empty;
        return writtenSpan;
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
    public void WriteBytes(scoped ReadOnlySpan<byte> bytes)
    {
        bytes.CopyTo(_buffer[_writeOffset..]);
        _writeOffset += bytes.Length;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteBytesString(scoped ReadOnlySpan<byte> bytes)
    {
        WriteUint32((uint)bytes.Length);
        WriteBytes(bytes);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteUnsignedAsMPint(scoped ReadOnlySpan<byte> bytes)
    {
        _writeOffset += SshPrimitives.WriteUnsignedAsMPint(bytes, _buffer[_writeOffset..]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteUint32(uint value)
    {
        SshPrimitives.WriteUint32(_buffer.Slice(_writeOffset, sizeof(uint)), value);
        _writeOffset += sizeof(uint);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteCryptoRandomBytes(int length)
    {
        RandomNumberGenerator.Fill(_buffer.Slice(_writeOffset, length));
        _writeOffset += length;
    }

    public void WriteString(string str)
    {
        var length = Encoding.UTF8.GetByteCount(str);
        WriteUint32((uint)length);
        Encoding.UTF8.GetBytes(str, _buffer.Slice(_writeOffset, length));
        _writeOffset += length;
    }

    public void WriteNameList(IReadOnlyList<IAlgorithmId> algorithms)
    {
        var lengthSpan = _buffer.Slice(_writeOffset, sizeof(uint));
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

                idBytes.CopyTo(_buffer.Slice(_writeOffset, idBytes.Length));
                _writeOffset += idBytes.Length;
                length += (uint)idBytes.Length;
            }
        }

        SshPrimitives.WriteUint32(lengthSpan, length);
    }

    public void WriteNoneNameList()
    {
        var target = _buffer.Slice(_writeOffset, 8);
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
