using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;
using System.Buffers;
using System.IO.Pipelines;

namespace Dragonhill.SlimSSH.IO;

internal sealed class SshPacketReader
{
    private readonly Stream _stream;
    private readonly AlgorithmContext _algorithmContext;
    private readonly ISshPacketEventHandler _packetEventHandler;

    private uint _sequenceNumber;

    public SshPacketReader(Stream stream, AlgorithmContext algorithmContext, ISshPacketEventHandler packetEventHandler)
    {
        _stream = stream;
        _algorithmContext = algorithmContext;
        _packetEventHandler = packetEventHandler;
    }

    public async Task Run(CancellationToken cancellationToken)
    {
        Pipe pipe = new();

        var streamReaderTask = StreamReader(pipe.Writer, cancellationToken);
        var messageProcessorTask = MessageProcessor(pipe.Reader, cancellationToken);

        var firstCompletedTask = await Task.WhenAny(streamReaderTask, messageProcessorTask);

        await pipe.Reader.CompleteAsync();
        await pipe.Writer.CompleteAsync();

        // propagate possible exceptions of the tasks
        await firstCompletedTask;
        await (firstCompletedTask == streamReaderTask ? messageProcessorTask : streamReaderTask);
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
        catch(OperationCanceledException)
        {
            // cancellation token was triggered, just return, run will stop everything when the first task completes
        }
    }

    private async Task MessageProcessor(PipeReader pipeReader, CancellationToken cancellationToken)
    {
        var isVersionRead = false;

        for (;;)
        {
            try
            {
                var readResult = await pipeReader.ReadAsync(cancellationToken);

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
                    var peerVersion = SshProtocolVersion.TryReadProtocolVersionExchange(inputBuffer, out consumedRange);
                    if (peerVersion != null)
                    {
                        isVersionRead = true;
                        _packetEventHandler.OnProtocolVersionRead(peerVersion);
                    }
                }
                else
                {
                    using var plaintextBuffer = TryReadBinaryPacket(inputBuffer, out var consumedBytes);
                    if (plaintextBuffer != null)
                    {
                        consumedRange = inputBuffer.GetPosition(consumedBytes, inputBuffer.Start);
                        await _packetEventHandler.OnPacketReceived(plaintextBuffer, consumedBytes);
                    }
                    else
                    {
                        consumedRange = null;
                    }
                }

                if (!consumedRange.HasValue)
                {
                    if (readResult.IsCompleted)
                    {
                        return;
                    }

                    // more data required, nothing consumed yet
                    pipeReader.AdvanceTo(inputBuffer.Start, inputBuffer.End);
                }
                else
                {
                    pipeReader.AdvanceTo(consumedRange.Value);
                }
            }
            catch (TaskCanceledException)
            {
                // cancellation token was triggered, just return, run will stop everything when the first task completes
            }
        }
    }

    private SshPacketPlaintextBuffer? TryReadBinaryPacket(ReadOnlySequence<byte> inputSequence, out int consumedBytes)
    {
        if (inputSequence.Length < _algorithmContext.RequiredBytesToDecryptLength)
        {
            consumedBytes = -1;
            return null;
        }

        Span<byte> packetStartCiphertext = stackalloc byte[_algorithmContext.RequiredBytesToDecryptLength];
        inputSequence.Slice(0, _algorithmContext.RequiredBytesToDecryptLength).CopyTo(packetStartCiphertext);
        Span<byte> packetStartPlaintext = stackalloc byte[_algorithmContext.RequiredBytesToDecryptLength];

        var decryptedStartBytes = _algorithmContext.DecryptLength(_sequenceNumber, packetStartCiphertext, packetStartPlaintext);
        var length = SshPrimitives.ReadUint32(packetStartPlaintext);

        if (length > Constants.MaxAllowedPacketSize)
        {
            throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Packet_TooLarge);
        }

        var lengthInt = (int)length;

        var totalPacketLengthWithoutMac = sizeof(uint) + lengthInt;
        var totalPacketCryptoLengthWithoutMac = totalPacketLengthWithoutMac + _algorithmContext.DecryptionAdditionalCryptoBytes;
        var totalPacketCryptoAndMacLength = totalPacketCryptoLengthWithoutMac + _algorithmContext.MacValidationLength;

        if (inputSequence.Length < totalPacketCryptoAndMacLength)
        {
            consumedBytes = -1;
            return null;
        }

        var ciphertextBuffer = ArrayPool<byte>.Shared.Rent(totalPacketCryptoAndMacLength);

        try
        {
            inputSequence.Slice(0, totalPacketCryptoAndMacLength).CopyTo(ciphertextBuffer);

            var plaintextBuffer = new SshPacketPlaintextBuffer(lengthInt, true);

            try
            {
                var rawPacketPlaintext = plaintextBuffer.GetWritableRawPacketSpan(totalPacketLengthWithoutMac);

                packetStartPlaintext[..decryptedStartBytes].CopyTo(rawPacketPlaintext);

                plaintextBuffer.WriteSequenceNumber(_sequenceNumber);

                _algorithmContext.Decrypt(_sequenceNumber, ciphertextBuffer.AsSpan(0, totalPacketCryptoAndMacLength), rawPacketPlaintext);

                ++_sequenceNumber;

                plaintextBuffer.FinishWriting(totalPacketLengthWithoutMac);

                if (!_algorithmContext.ValidateMac(plaintextBuffer.GetSequenceNumberAndRawPacketSpan(), ciphertextBuffer.AsSpan(totalPacketCryptoAndMacLength, _algorithmContext.MacValidationLength)))
                {
                    throw new SshException(DisconnectReasonCode.MacError, Strings.Packet_MacError);
                }

                if (!_algorithmContext.ValidateDecryptionPayloadAndPaddingLength(plaintextBuffer.PayloadLength, plaintextBuffer.PaddingLength))
                {
                    throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Packet_PaddingError);
                }

                consumedBytes = totalPacketLengthWithoutMac;

                return plaintextBuffer;
            }
            catch
            {
                plaintextBuffer.Dispose();
                throw;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ciphertextBuffer);
        }
    }

}
