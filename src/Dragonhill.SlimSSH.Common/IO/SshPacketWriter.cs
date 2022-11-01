using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Threading;
using System.Buffers;
using System.Threading.Channels;

namespace Dragonhill.SlimSSH.IO;

internal sealed class SshPacketWriter : ISshPacketWriter
{
    private const int MaxInFlightMessages = 5;

    private readonly FifoSingleSemaphore _semaphore = new();
    private readonly Channel<(byte[]?, Memory<byte>)> _streamQueue = Channel.CreateBounded<(byte[]?, Memory<byte>)>(MaxInFlightMessages);

    private readonly Stream _stream;
    private readonly AlgorithmContext _algorithmContext;

    private uint _sequenceNumber;

    public SshPacketWriter(Stream stream, AlgorithmContext algorithmContext)
    {
        _stream = stream;
        _algorithmContext = algorithmContext;
    }

    public int RequiredBytesInFrontOfBuffer => sizeof(uint);

    public int MaxPaddingSize => _algorithmContext.AvailableSshAlgorithms.Metrics.MaxPaddingSize;

    /// <remarks>The first <see cref="RequiredBytesInFrontOfBuffer"/> bytes of the memory must not be used as they will be overwritten</remarks>
    public async ValueTask WritePacket(SshUnfinishedPacket unfinishedPacket)
    {
        try
        {
            using (await _semaphore.WaitToEnter())
            {
                var packetPlaintextWithAdditional = unfinishedPacket.FinishPacket(_algorithmContext.EncryptionEffectivePaddingSize);

                SshPrimitives.WriteUint32(packetPlaintextWithAdditional.Span, _sequenceNumber);

                var ciphertextLength = packetPlaintextWithAdditional.Length - RequiredBytesInFrontOfBuffer;

                var ciphertextAndMacLength = packetPlaintextWithAdditional.Length - RequiredBytesInFrontOfBuffer + _algorithmContext.MacGenerationLength;

                var ciphertextBuffer = ArrayPool<byte>.Shared.Rent(ciphertextAndMacLength);

                try
                {
                    var plaintextWithoutAdditional = packetPlaintextWithAdditional[RequiredBytesInFrontOfBuffer..];

                    _algorithmContext.Encrypt(_sequenceNumber, plaintextWithoutAdditional.Span, ciphertextBuffer.AsSpan(0, ciphertextLength));

                    _algorithmContext.GenerateMac(packetPlaintextWithAdditional.Span, ciphertextBuffer.AsSpan(ciphertextLength, _algorithmContext.MacGenerationLength));

                    ++_sequenceNumber;

                    await _algorithmContext.OnPacketWrite(plaintextWithoutAdditional.Span, out var stopSending);

                    await _streamQueue.Writer.WriteAsync((ciphertextBuffer, ciphertextBuffer.AsMemory(0, ciphertextAndMacLength)));

                    if (stopSending)
                    {
                        _streamQueue.Writer.TryComplete(); // close the channel if this is the last message to be sent
                    }
                }
                catch
                {
                    ArrayPool<byte>.Shared.Return(ciphertextBuffer);

                    throw;
                }
            }
        }
        catch
        {
            // if there was an exception -  close the channel
            _streamQueue.Writer.TryComplete();
            throw;
        }
    }

    private async ValueTask WriteVersion()
    {
        using (await _semaphore.WaitToEnter())
        {
            await _streamQueue.Writer.WriteAsync((null, SshProtocolVersion.OwnVersion.AsMemory()));
        }
    }

    public async Task Run(CancellationToken cancellationToken)
    {
        await WriteVersion();

        for (;;)
        {
            byte[]? buffer = null;

            try
            {
                (buffer, var memory) = await _streamQueue.Reader.ReadAsync(cancellationToken);
                await _stream.WriteAsync(memory, cancellationToken);
            }
            catch (ChannelClosedException) // channel has been closed and is empty
            {
                return;
            }
            catch(Exception exception)
            {
                _streamQueue.Writer.TryComplete();

                while (_streamQueue.Reader.TryRead(out var entry))
                {
                    if (entry.Item1 != null)
                    {
                        ArrayPool<byte>.Shared.Return(entry.Item1);
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
                if (buffer != null)
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
        }
    }
}
