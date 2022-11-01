using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading.Channels;

namespace Dragonhill.SlimSSH.IO;

internal sealed class SshPacketReader : ISshPacketReader
{
    private const int MaxInFlightMessages = 5;

    private readonly Pipe _inputPipe = new();
    private readonly Channel<PooledBufferWrapper> _readQueue = Channel.CreateBounded<PooledBufferWrapper>(MaxInFlightMessages);

    private readonly Stream _stream;
    private readonly AlgorithmContext _algorithmContext;

    private uint _sequenceNumber;

    private SshProtocolVersion? _peerVersion;

    public SshProtocolVersion? PeerVersion => _peerVersion;

    public SshPacketReader(Stream stream, AlgorithmContext algorithmContext)
    {
        _stream = stream;
        _algorithmContext = algorithmContext;
    }

    public async Task Run(CancellationToken cancellationToken)
    {
        var streamReaderTask = StreamReader(_inputPipe.Writer, cancellationToken);
        var messageProcessorTask = MessageProcessor();

        var finishedTask = await Task.WhenAny(streamReaderTask, messageProcessorTask);

        await ClosePipeAndQueue(false);

        // await the finished task to propagate any exceptions
        await finishedTask;

        var otherTask = streamReaderTask == finishedTask ? messageProcessorTask : streamReaderTask;

        await otherTask;
    }

    /// <remarks>
    /// Note: The caller is responsible for calling <see cref="PooledBufferWrapper.Dispose"/> if the return value is not null.
    /// </remarks>
    public async ValueTask<PooledBufferWrapper?> ReadPacket()
    {
        try
        {
            return await _readQueue.Reader.ReadAsync();
        }
        catch (ChannelClosedException)
        {
            return null;
        }
        catch
        {
            await ClosePipeAndQueue(true);
            throw;
        }
    }

    private async ValueTask ClosePipeAndQueue(bool drain)
    {
        // Close the pipes so no more data processing will happen
        await _inputPipe.Reader.CompleteAsync();
        await _inputPipe.Writer.CompleteAsync();

        // Drain the queue and return everything to the array pool
        _readQueue.Writer.TryComplete();
        if (drain)
        {
            while (_readQueue.Reader.TryRead(out var entry))
            {
                entry.Dispose();
            }
        }
    }

    private async Task MessageProcessor()
    {
        var isVersionRead = false;

        try
        {
            for (;;)
            {
                var readResult = await _inputPipe.Reader.ReadAsync();

                if (readResult.IsCanceled)
                {
                    return;
                }

                var inputBuffer = readResult.Buffer;

                if (inputBuffer.IsEmpty)
                {
                    return;
                }

                SequencePosition? consumedRange;

                if (!isVersionRead)
                {
                    if (SshProtocolVersion.TryReadProtocolVersionExchange(inputBuffer, out consumedRange, out _peerVersion))
                    {
                        isVersionRead = true;
                    }
                }
                else
                {
                    if (TryReadBinaryPacket(inputBuffer, out consumedRange, out var bufferWrapper))
                    {
                        try
                        {
                            await _algorithmContext.OnPacketRead(bufferWrapper!.Value.AsSpan(), out var stopReceiving);

                            await _readQueue.Writer.WriteAsync(bufferWrapper.Value);

                            if (stopReceiving)
                            {
                                await ClosePipeAndQueue(false);

                                return; // done processing
                            }
                        }
                        catch
                        {
                            bufferWrapper!.Value.Dispose();
                            throw;
                        }
                    }
                }

                if (!consumedRange.HasValue)
                {
                    if (readResult.IsCompleted)
                    {
                        return;
                    }

                    // Need more data, consumed nothing yet
                    _inputPipe.Reader.AdvanceTo(inputBuffer.Start, inputBuffer.End);
                }
                else
                {
                    _inputPipe.Reader.AdvanceTo(consumedRange.Value);
                }
            }
        }
        catch
        {
            await ClosePipeAndQueue(false);
            throw;
        }
    }

    private bool TryReadBinaryPacket(ReadOnlySequence<byte> inputSequence, out SequencePosition? consumedRange, out PooledBufferWrapper? bufferWrapper)
    {
        if (inputSequence.Length < _algorithmContext.RequiredBytesToDecryptLength)
        {
            consumedRange = null;
            bufferWrapper = null;
            return false;
        }

        Span<byte> lengthCiphertext = stackalloc byte[_algorithmContext.RequiredBytesToDecryptLength];
        inputSequence.Slice(0, _algorithmContext.RequiredBytesToDecryptLength).CopyTo(lengthCiphertext);

        var length = _algorithmContext.DecryptLength(lengthCiphertext);

        // Check if the packet length is below the required payload length + 1 byte for the padding length field + maximum padding length
        if (length > Constants.MaxAllowedPacketSize)
        {
            throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Packet_TooLarge);
        }

        var lengthInt = (int)length;

        var packetLengthWithoutMac = 4 + lengthInt;
        var totalPacketLength = packetLengthWithoutMac + _algorithmContext.MacValidationLength;

        if (inputSequence.Length < totalPacketLength)
        {
            consumedRange = null;
            bufferWrapper = null;
            return false;
        }

        var ciphertextBuffer = ArrayPool<byte>.Shared.Rent(totalPacketLength);

        try
        {
            inputSequence.Slice(0, totalPacketLength).CopyTo(ciphertextBuffer);

            var plaintextBufferMinSize = packetLengthWithoutMac + sizeof(uint);

            var plaintextBuffer = ArrayPool<byte>.Shared.Rent(plaintextBufferMinSize);

            try
            {
                SshPrimitives.WriteUint32(plaintextBuffer, _sequenceNumber);
                var binaryPacketPlaintextSpan = plaintextBuffer.AsSpan(sizeof(uint), packetLengthWithoutMac);
                _algorithmContext.Decrypt(ciphertextBuffer.AsSpan(0, packetLengthWithoutMac), binaryPacketPlaintextSpan);

                if (!_algorithmContext.ValidateMac(plaintextBuffer.AsSpan(0, plaintextBufferMinSize), ciphertextBuffer.AsSpan(packetLengthWithoutMac, _algorithmContext.MacValidationLength)))
                {
                    throw new SshException(DisconnectReasonCode.MacError, Strings.Packet_MacError);
                }

                var payloadSize = lengthInt - (binaryPacketPlaintextSpan[4] + 1);

                if (payloadSize < 1)
                {
                    throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Packet_NoMessageId);
                }

                consumedRange = inputSequence.GetPosition(totalPacketLength, inputSequence.Start);

                ++_sequenceNumber;

                bufferWrapper = new PooledBufferWrapper(plaintextBuffer, sizeof(uint), packetLengthWithoutMac);

                return true;
            }
            catch
            {
                ArrayPool<byte>.Shared.Return(plaintextBuffer);
                throw;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ciphertextBuffer);
        }
    }

    private async Task StreamReader(PipeWriter pipeWriter, CancellationToken cancellationToken)
    {
        try
        {
            for (;;)
            {
                var writerMemory = pipeWriter.GetMemory();

                var bytesRead = await _stream.ReadAsync(writerMemory, cancellationToken);
                if (bytesRead == 0)
                {
                    break;
                }

                pipeWriter.Advance(bytesRead);

                var result = await pipeWriter.FlushAsync(cancellationToken);

                if (result.IsCompleted)
                {
                    break;
                }
            }

            await pipeWriter.CompleteAsync();
        }
        catch
        {
            await ClosePipeAndQueue(false);
            throw;
        }
    }

    public ValueTask DisposeAsync()
    {
        return ClosePipeAndQueue(true);
    }
}
