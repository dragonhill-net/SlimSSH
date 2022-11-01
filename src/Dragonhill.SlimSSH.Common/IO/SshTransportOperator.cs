using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;
using System.Buffers;

namespace Dragonhill.SlimSSH.IO;

internal class SshTransportOperator : IAsyncDisposable, ISshTransportOperator, ISafePacketSender
{
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    private readonly AlgorithmContext _algorithmContext;
    private readonly ISshPacketReader _reader;
    private readonly ISshPacketWriter _writer;
    private readonly Task _readerTask;
    private readonly Task _writerTask;

    private SpinLock _kexLock; // not readonly as the struct needs to be mutable

    private readonly KexContext _kexContext = new();
    private bool _kexInProgress = false;
    private bool _kexInitReceived = false;

    public SshProtocolVersion? PeerVersion => _reader.PeerVersion;

    public SshTransportOperator(IAvailableSshAlgorithms availableSshAlgorithms, Stream stream, Func<Stream, AlgorithmContext, (ISshPacketReader, ISshPacketWriter)> sshReaderWriterFactory)
    {
        _algorithmContext = new AlgorithmContext(availableSshAlgorithms, this);
        (_reader, _writer) = sshReaderWriterFactory(stream, _algorithmContext);

        _readerTask = _reader.Run(_cancellationTokenSource.Token);
        _writerTask = _writer.Run(_cancellationTokenSource.Token);
    }

    public async ValueTask GenerateAndSend(PackageBuilderAction builder, int? payloadSize = null)
    {
        var packetBuilder = payloadSize.HasValue ? new SshPacketBuilder(_writer, payloadSize.Value) : new SshPacketBuilder(_writer);

        try
        {
            builder(_kexContext, ref packetBuilder);
            await WritePacket(packetBuilder.GetUnfinishedPacket());
        }
        finally
        {
            packetBuilder.Dispose();
        }
    }

    public ReadOnlySpan<byte> PeerVersionBytesWithoutCrLf => PeerVersion!.Value.VersionBytesWithoutCrLf;

    private async ValueTask WritePacket(SshUnfinishedPacket unfinishedPacket)
    {
        try
        {
            await _writer.WritePacket(unfinishedPacket);
        }
        catch
        {
            // as the error was on write, sending a disconnect message is not going to work
            await WaitForCloseAndThrowPossibleErrors(null); // an error from the run task may be the original error source, so throw that instead if any
            throw;
        }
    }

    public async ValueTask<PooledBufferWrapper?> ReadPacket()
    {
        try
        {
            for (;;)
            {
                var packet = await _reader.ReadPacket();

                try
                {
                    if (!packet.HasValue)
                    {
                        await WaitForCloseAndThrowPossibleErrors(null);
                        return null;
                    }

                    var messageId = packet.Value.AsSpan()[PacketConstants.MessageIdOffset];

                    if (messageId == (byte)MessageId.KexInit)
                    {
                        await ProcessIncomingKexInit(packet.Value);
                        packet = null; // mark packet consumed (as it is kept for the duration of the KEX)
                        continue;
                    }

                    if (_kexInProgress)
                    {
                        if (_kexContext.ShouldIgnoreThisKexPacket())
                        {
                            continue;
                        }

                        if (await _kexContext.KexAlgorithm!.FilterPacket(_kexContext, messageId, packet.Value.GetPayloadMemory(), this))
                        {
                            continue;
                        }
                    }

                    var retval = packet.Value;
                    packet = null;
                    return retval;
                }
                finally
                {
                    packet?.Dispose();
                }
            }
        }
        catch (SshException exception) // at least try to send a disconnect when getting a read error
        {
            await WaitForCloseAndThrowPossibleErrors(exception.DisconnectReason); // an error from the run task may be the original error source, so throw that instead if any
            throw;
        }
        catch
        {
            await WaitForCloseAndThrowPossibleErrors(DisconnectReasonCode.ByApplication); // an error from the run task may be the original error source, so throw that instead if any
            throw;
        }
    }

    public async ValueTask Disconnect(DisconnectReasonCode disconnectReasonCode)
    {
        if (disconnectReasonCode == DisconnectReasonCode.None)
        {
            disconnectReasonCode = DisconnectReasonCode.ByApplication;
        }

        var packetBuilder = new SshPacketBuilder(_writer);

        try
        {
            packetBuilder.WriteMessageId(MessageId.Disconnect);

            packetBuilder.WriteUint32((uint)disconnectReasonCode);
            packetBuilder.WriteString(disconnectReasonCode.ToString());
            packetBuilder.WriteString("en");

            await _writer.WritePacket(packetBuilder.GetUnfinishedPacket());
        }
        catch
        {
            packetBuilder.Dispose();
            throw;
        }
    }

    async ValueTask ISshTransportOperator.RequestKeyExchange()
    {
        var lockTaken = false;

        try
        {
            _kexLock.Enter(ref lockTaken);

            if (_kexInProgress)
            {
                return;
            }

            _kexInProgress = true;
        }
        finally
        {
            if (lockTaken)
            {
                _kexLock.Exit();
            }
        }

        _kexContext.SetOwnKexInit(await KexExecutor.SendKexInit(_algorithmContext.AvailableSshAlgorithms, _writer));
    }

    private async ValueTask ProcessIncomingKexInit(PooledBufferWrapper packet)
    {

        var sendKexInit = false;
        var lockTaken = false;

        try
        {
            _kexLock.Enter(ref lockTaken);

            if (_kexInitReceived)
            {
                throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Transport_KexInitWhileKexActive);
            }

            if (!_kexInProgress)
            {
                sendKexInit = true;
                _kexInProgress = true;
            }

            _kexInitReceived = true;
        }
        finally
        {
            if (lockTaken)
            {
                _kexLock.Exit();
            }
        }

        if (sendKexInit)
        {
            _kexContext.SetOwnKexInit(await KexExecutor.SendKexInit(_algorithmContext.AvailableSshAlgorithms, _writer));
        }

        _kexContext.SetPeerKexInit(packet);

        await KexExecutor.StartKex(_algorithmContext, _kexContext, this);

    }

    private async ValueTask WaitForCloseAndThrowPossibleErrors(DisconnectReasonCode? disconnectReasonCode)
    {
        // try to send the disconnect message
        if (disconnectReasonCode.HasValue && !_writerTask.IsCompleted)
        {
            try
            {
                await Disconnect(disconnectReasonCode.Value);
                await _writerTask; //TODO: place for timeout
            }
            catch
            {
                // best effort only, if it doesn't work can't do anything
            }
        }

        _cancellationTokenSource.Cancel();

        try
        {
            var finishedTask = await Task.WhenAny(_readerTask, _writerTask);

            await finishedTask; // propagate possible exception

            var otherTask = finishedTask == _readerTask ? _writerTask : _readerTask;

            await otherTask; // propagate possible exception
        }
        finally
        {
            var lockTaken = false;

            try
            {
                _kexLock.Enter(ref lockTaken);

                _kexContext.Reset();

                await _reader.DisposeAsync();
            }
            finally
            {
                if (lockTaken)
                {
                    _kexLock.Exit();
                }
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        return WaitForCloseAndThrowPossibleErrors(null);
    }
}
