using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Helpers;
using System.Buffers;
using System.Threading.Channels;

namespace Dragonhill.SlimSSH.IO;

internal sealed class SshPacketWriter
{
    private const int MaxInFlightMessages = 5;

    private readonly Channel<(Memory<byte>, byte[]?)> _streamQueue = Channel.CreateBounded<(Memory<byte>, byte[]?)>(MaxInFlightMessages);

    private readonly Stream _stream;
    private readonly AlgorithmContext _algorithmContext;
    private readonly ISshPacketEventHandler _packetEventHandler;

    private uint _sequenceNumber;

    public SshPacketWriter(Stream stream, AlgorithmContext algorithmContext, ISshPacketEventHandler packetEventHandler)
    {
        _stream = stream;
        _algorithmContext = algorithmContext;
        _packetEventHandler = packetEventHandler;
    }

    public void FinishWriting()
    {
        _streamQueue.Writer.Complete();
    }

    public async ValueTask WritePacket(SshPacketPlaintextBuffer packetPlaintext, CancellationToken cancellationToken)
    {
        var packetPlaintextLengthWithoutMac = packetPlaintext.FinishPacket(_algorithmContext);

        var macGenerationLength = _algorithmContext.MacGenerationLength;

        var ciphertextLengthWithoutMac = packetPlaintextLengthWithoutMac + _algorithmContext.EncryptionAdditionalCryptoBytes;

        var ciphertextTotalLength = ciphertextLengthWithoutMac + _algorithmContext.MacGenerationLength;

        var ciphertextBuffer = ArrayPool<byte>.Shared.Rent(ciphertextTotalLength);

        try
        {
            packetPlaintext.WriteSequenceNumber(_sequenceNumber);

            _algorithmContext.Encrypt(_sequenceNumber, packetPlaintext.GetRawPacketSpan(), ciphertextBuffer.AsSpan(0, ciphertextLengthWithoutMac));

            if (macGenerationLength > 0)
            {
                _algorithmContext.GenerateMac(packetPlaintext.GetSequenceNumberAndRawPacketSpan(), ciphertextBuffer.AsSpan(ciphertextLengthWithoutMac, macGenerationLength));
            }

            ++_sequenceNumber;

            await _streamQueue.Writer.WriteAsync((ciphertextBuffer.AsMemory(0, ciphertextTotalLength), ciphertextBuffer), cancellationToken);
        }
        catch(Exception exception)
        {
            ArrayPool<byte>.Shared.Return(ciphertextBuffer);

            _streamQueue.Writer.Complete();

            if (exception is not OperationCanceledException)
            {
                throw;
            }

            // if the operation was cancelled - must not call the OnAfterPacketSend handler
            return;
        }

        // outside try/catch - if it throws an exception the buffer is already owned by the queue
        await _packetEventHandler.OnAfterPacketSend(packetPlaintext, ciphertextTotalLength);
    }

    public async Task Run(CancellationToken cancellationToken)
    {
        await WriteVersion();

        for (;;)
        {
            byte[]? arrayPoolBuffer = null;

            try
            {
                (var memory, arrayPoolBuffer) = await _streamQueue.Reader.ReadAsync(cancellationToken);
                await _stream.WriteAsync(memory, cancellationToken);
            }
            catch (ChannelClosedException) // channel has been closed and is empty
            {
                return;
            }
            catch (Exception exception)
            {
                _streamQueue.Writer.TryComplete();

                while (_streamQueue.Reader.TryRead(out var entry))
                {
                    if (entry.Item2 != null)
                    {
                        ArrayPool<byte>.Shared.Return(entry.Item2);
                    }
                }

                if (exception is OperationCanceledException)
                {
                    return;
                }

                throw;
            }
            finally
            {
                if (arrayPoolBuffer != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayPoolBuffer);
                }
            }
        }
    }

    private ValueTask WriteVersion()
    {
        return _streamQueue.Writer.WriteAsync((SshProtocolVersion.OwnVersion, null));
    }
}
