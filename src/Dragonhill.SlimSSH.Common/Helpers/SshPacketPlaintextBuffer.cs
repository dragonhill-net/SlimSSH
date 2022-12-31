using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Protocol;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace Dragonhill.SlimSSH.Helpers;

/// <remarks>
/// Note: to be able to clear the buffer without resorting to expensive finalizers, this class is reference counted!
/// At the beginning of the buffer, there is always room for an uint32 for the sequence number, which is used for validating and generating the MAC.
/// </remarks>
public class SshPacketPlaintextBuffer : IDisposable
{
    private const int PacketOffset = sizeof(uint);

    private readonly bool _clearOnReturn;

    private SpinLock _lock = new();
    private int _referenceCount;
    private byte[] _buffer;
    private int _payloadLength;
    private int _usedBuffer;
    public int PayloadLength => _payloadLength;
    public byte PaddingLength => _buffer[PacketOffset + PacketConstants.PaddingLengthOffset];

    public byte MessageId => _buffer[PacketOffset + PacketConstants.MessageIdOffset];

    public static SshPacketPlaintextBuffer CreateDefault(bool clearOnReturn)
    {
        // according to the RFC 4253 packets 35000 of total packet size must be supported (excluding packet length, padding size, padding and mac)
        return new SshPacketPlaintextBuffer(Constants.RequiredSupportedRawPacketSize, clearOnReturn);
    }

    /// <summary>
    /// Initializes a new instance and rents a buffer for it.
    /// </summary>
    /// <param name="packetLength">The size of the packet excluding the uint32 required for the packet length field itself.</param>
    /// <param name="clearOnReturn">Set to true if the buffer should be cleared after usage.</param>
    /// <remarks>
    /// The <see cref="Dispose"/> method must be called exactly once! But it has to be called, else there will be a memory leak.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public SshPacketPlaintextBuffer(int packetLength, bool clearOnReturn)
    {
        // the size of the requested buffer is the given packet length + room for the sequence number and the packet length field itself
        _referenceCount = 1;
        _buffer = ArrayPool<byte>.Shared.Rent(packetLength + 2 * sizeof(uint));
        _clearOnReturn = clearOnReturn;
        _payloadLength = -1;
        _usedBuffer = PacketOffset;
    }

    /// <summary>
    /// For each call to claim there must be a call to dispose, each new instance starts with one claim.
    /// </summary>
    /// <returns>A reference to itself.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public SshPacketPlaintextBuffer Claim()
    {
        var lockTaken = false;
        try
        {
            _lock.Enter(ref lockTaken);
            if (_referenceCount == 0)
            {
                SshExceptionThrowHelper.ReferenceCountZero();
            }

            ++_referenceCount;
        }
        finally
        {
            if (lockTaken)
            {
                _lock.Exit(false);
            }
        }

        return this;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Dispose()
    {
        var lockTaken = false;
        var cleanup = false;
        try
        {
            _lock.Enter(ref lockTaken);
            if (_referenceCount == 1)
            {
                _referenceCount = 0;
                cleanup = true;
            }
            else
            {
                --_referenceCount;
            }
        }
        finally
        {
            if (lockTaken)
            {
                _lock.Exit(false);
            }
        }

        if (cleanup)
        {
            ArrayPool<byte>.Shared.Return(_buffer, _clearOnReturn);
            _buffer = Array.Empty<byte>();
            _payloadLength = -1;
            _usedBuffer = 0;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public SshDeserializer GetPayloadDeserializerAfterMessageId()
    {
        return new SshDeserializer(_buffer.AsSpan(PacketOffset + PacketConstants.AfterMessageIdOffset, _payloadLength - 1));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void WriteSequenceNumber(uint sequenceNumber)
    {
        SshPrimitives.WriteUint32(_buffer, sequenceNumber);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal ReadOnlySpan<byte> GetRawPacketSpan()
    {
        return _buffer.AsSpan(PacketOffset, _usedBuffer - PacketOffset);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadOnlySpan<byte> GetPayloadSpan()
    {
        return _buffer.AsSpan(PacketOffset + PacketConstants.PayloadOffset, _payloadLength);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal ReadOnlySpan<byte> GetSequenceNumberAndRawPacketSpan()
    {
        return _buffer.AsSpan(0, _usedBuffer);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal Span<byte> GetWritableRawPacketSpan(int rawPacketLength)
    {
        return _buffer.AsSpan(PacketOffset, rawPacketLength);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal Span<byte> GetWritablePayloadAndPaddingSpan()
    {
        return _buffer.AsSpan(PacketOffset + PacketConstants.PayloadOffset);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void FinishWriting(int totalPacketLength)
    {
        _payloadLength = totalPacketLength - _buffer[PacketOffset + PacketConstants.PaddingLengthOffset] - 1 - sizeof(uint);
        _usedBuffer = PacketOffset + totalPacketLength;

        if (_payloadLength < 1)
        {
            SshExceptionThrowHelper.NoMessageId();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void FinishWritingPayload(int payloadLength)
    {
        if (payloadLength < 1)
        {
            SshExceptionThrowHelper.NoMessageId();
        }

        _payloadLength = payloadLength;
    }

    /// <summary>
    /// Sets the padding and packet length according to the current payload length
    /// </summary>
    /// <returns>The total length of the packet (including the packet length field)</returns>
    internal int FinishPacket(AlgorithmContext context)
    {
        var paddingStart = PacketOffset + PacketConstants.PacketLengthAndPaddingLengthSize + _payloadLength;

        var paddingAmount = context.EncryptionApplyPadding(_buffer.AsSpan(paddingStart), _payloadLength);

        var packetLength = PacketConstants.PaddingLengthSize + _payloadLength + paddingAmount;

        // update the packet length and padding length fields
        SshPrimitives.WriteUint32(_buffer.AsSpan(PacketOffset + PacketConstants.PacketLengthOffset), (uint)packetLength);
        _buffer[PacketOffset + PacketConstants.PaddingLengthOffset] = paddingAmount;

        var totalPacketLength = packetLength + PacketConstants.PacketLengthSize;

        _usedBuffer = PacketOffset + totalPacketLength;

        return totalPacketLength;
    }
}
