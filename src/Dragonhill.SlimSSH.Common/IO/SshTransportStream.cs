using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Collections;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;
using Dragonhill.SlimSSH.Protocol.Packets;
using Dragonhill.SlimSSH.Threading;
using System.Text;

namespace Dragonhill.SlimSSH.IO;

public sealed class SshTransportStream : ISshPacketEventHandler, ITimerHandler
{
    [Flags]
    private enum ConnectionState: byte
    {
        FinalStateFlag = 0b1000_0000,
        TerminationStateFlag = 0b0100_0000,

        Unconnected = 0,
        Unauthenticated = 0b0000_0001,
        Authenticated = 0b0000_0010,
        SelfDisconnectSend = TerminationStateFlag | 0b0000_0100,
        SelfDisconnected = FinalStateFlag | TerminationStateFlag | 0b0000_1000,
        PeerDisconnected = FinalStateFlag | TerminationStateFlag | 0b0000_1001,
        Failed = FinalStateFlag | TerminationStateFlag | 0b0000_1111
    }

    private readonly Stream _stream;

    private static readonly Lazy<FixedDelayTimer> KexTimer = new(() =>
    {
        var period = TimeSpan.FromMilliseconds(Constants.KexAfterMilliseconds);
        var tolerance = period / 200;
        return new FixedDelayTimer(period, tolerance);
    });

    private readonly object _lock = new();

    private readonly CancellationTokenSource _readCancellationTokenSource = new();
    private readonly CancellationTokenSource _writeCancellationTokenSource = new();

    private readonly AlgorithmContext _algorithmContext = new();
    private readonly SshPacketReader _reader;
    private readonly SshPacketWriter _writer;
    private readonly KexExecutor _kexExecutor;

    private readonly FifoQueueWithPriorityMode _writerFifoQueueWithPriorityMode = new();

    private FixedDelayTimer.Entry? _kexTimerEntry;

    private bool _filterKexPackets;

    private int _bytesRead;
    private int _bytesWritten;

    private TaskCompletionSource? _connectCompletedSource;
    private Task? _runTask;

    public SshProtocolVersion? PeerVersion { get; private set; }

    private ConnectionState _connectionState = ConnectionState.Unconnected;
    public Exception? FirstRelevantException { get; private set; }

    //public Exception? ErrorState { get; private set; }

    public SshTransportStream(IAvailableSshAlgorithms availableSshAlgorithms, Stream stream)
    {
        _stream = stream;

        _reader = new SshPacketReader(stream, _algorithmContext, this);
        _writer = new SshPacketWriter(stream, _algorithmContext, this);

        _kexExecutor = new KexExecutor(availableSshAlgorithms, _algorithmContext, _writerFifoQueueWithPriorityMode);
    }

    public async Task Connect(CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (_connectionState != ConnectionState.Unconnected)
            {
                throw new SshException(Strings.SshConnectionBase_ConnectCalledTwice);
            }

            _connectionState = ConnectionState.Unauthenticated;
        }

        _runTask = Run();

        _connectCompletedSource = new TaskCompletionSource();

        try
        {
            await _connectCompletedSource.Task.WaitAsync(cancellationToken);

            if (cancellationToken.IsCancellationRequested)
            {
                _readCancellationTokenSource.Cancel();
                _writeCancellationTokenSource.Cancel();
                await _stream.DisposeAsync();
            }

            _kexTimerEntry = KexTimer.Value.Register(this);
        }
        finally
        {
            _connectCompletedSource = null;
        }
    }

    void ISshPacketEventHandler.OnProtocolVersionRead(SshProtocolVersion sshProtocolVersion)
    {
        PeerVersion = sshProtocolVersion;
        _kexExecutor.PeerVersion = sshProtocolVersion;
    }

    ValueTask ISshPacketEventHandler.OnPacketReceived(SshPacketPlaintextBuffer plaintextBuffer, int totalBytes)
    {
        _bytesRead += totalBytes;

        if (_filterKexPackets)
        {

            if (_kexExecutor.ShouldIgnorePacket())
            {
                return ValueTask.CompletedTask;
            }

            if (_kexExecutor.WantsPacket(plaintextBuffer.MessageId))
            {
                return _kexExecutor.FilterPacket(plaintextBuffer);
            }
        }

        switch (plaintextBuffer.MessageId)
        {
            case (byte)MessageId.KexInit:
                _filterKexPackets = true;
                return _kexExecutor.ProcessIncomingKexInit(plaintextBuffer);

            case (byte)MessageId.NewKeys:
                _bytesRead = 0;
                _filterKexPackets = false;
                _kexExecutor.ProcessIncomingNewKeys();
                return ValueTask.CompletedTask;

            case (byte)MessageId.Disconnect:
                return OnPeerDisconnected(plaintextBuffer);

            case (byte)MessageId.Unimplemented:
                SshExceptionThrowHelper.PeerUnimplemented();
                break;

            case (byte)MessageId.Debug: // currently ignored
            case (byte)MessageId.Ignore:
                break;

            default:
                SshExceptionThrowHelper.UnexpectedPacket();
                break;
        }

        if (_bytesRead > Constants.KexAfterBytes)
        {
            return _kexExecutor.TryInitKex();
        }

        return ValueTask.CompletedTask;
    }

    async ValueTask ITimerHandler.OnTimer()
    {
        try
        {
            await _kexExecutor.TryInitKex();
        }
        catch(Exception exception)
        {
            await SetErrorState(exception);
        }
    }

    ValueTask ISshPacketEventHandler.OnAfterPacketSend(SshPacketPlaintextBuffer plaintextBuffer, int totalBytes)
    {
        switch (plaintextBuffer.MessageId)
        {
            case (byte)MessageId.NewKeys:
                _bytesWritten = 0;
                _kexExecutor.ProcessOutgoingNewKeys();
                _connectCompletedSource?.TrySetResult();
                return ValueTask.CompletedTask;

            case (byte)MessageId.Disconnect:
                lock (_lock)
                {
                    if (_connectionState == ConnectionState.SelfDisconnectSend)
                    {
                        _connectionState = ConnectionState.SelfDisconnected;
                    }
                    else if(_connectionState != ConnectionState.Failed)
                    {
                        return SetErrorState(new SshException(Strings.Transport_UnexpectedDisconnect));
                    }
                }

                _readCancellationTokenSource.Cancel(); // cancel the reader we should not accept anything after sending a disconnect message

                return ValueTask.CompletedTask;
        }

        _bytesWritten += totalBytes;

        if (_bytesWritten > Constants.KexAfterBytes)
        {
            return _kexExecutor.TryInitKex();
        }

        return ValueTask.CompletedTask;
    }

    private async Task Run()
    {
        var reader = _reader.Run(_readCancellationTokenSource.Token);

        var writerCancellationToken = _writeCancellationTokenSource.Token;
        var writer = _writer.Run(writerCancellationToken);
        var pump = OutgoingMessagePump(writerCancellationToken);

        var runTasks = new List<Task>
            {
                reader, writer, pump
            };

        while (runTasks.Count > 0)
        {
            var awaitedTask = await Task.WhenAny(runTasks);

            var newErrorState = awaitedTask.Exception?.GetBaseException();

            if (newErrorState == null)
            {
                lock (_lock)
                {
                    if ((_connectionState & ConnectionState.TerminationStateFlag) == 0)
                    {
                        newErrorState = new SshException(Strings.Transport_UnexpectedClosed);
                    }
                }
            }

            if (newErrorState != null)
            {
                await SetErrorState(newErrorState);
            }

            runTasks.Remove(awaitedTask);

            _kexTimerEntry?.Dispose();
            _kexTimerEntry = null;
        }
    }

    private async Task OutgoingMessagePump(CancellationToken cancellationToken)
    {
        for (;;)
        {
            using var plaintextBuffer = await _writerFifoQueueWithPriorityMode.ReadAsync();

            // null result means the queue is closed
            if (plaintextBuffer == null)
            {
                break;
            }

            await _writer.WritePacket(plaintextBuffer, cancellationToken);
        }

        _writer.FinishWriting();
    }

    private ValueTask OnPeerDisconnected(SshPacketPlaintextBuffer plaintextBuffer)
    {
        var disconnectionMessageDeserializer = plaintextBuffer.GetPayloadDeserializerAfterMessageId();

        var reasonCode = disconnectionMessageDeserializer.ReadUint32();
        var description = disconnectionMessageDeserializer.ReadBytesString();
        disconnectionMessageDeserializer.ReadBytesString(); //Ignore the language tag for now
        disconnectionMessageDeserializer.CheckReadEverything();

        lock (_lock)
        {
            if ((_connectionState & ConnectionState.FinalStateFlag) == 0)
            {
                _connectionState = ConnectionState.PeerDisconnected;
                FirstRelevantException = new SshPeerDisconnectedException(reasonCode, Encoding.UTF8.GetString(description));
            }
        }

        // if the peer has sent a disconnect message, it will not accept anything else anyway
        _writerFifoQueueWithPriorityMode.Close();
        _readCancellationTokenSource.Cancel();
        _writeCancellationTokenSource.Cancel();
        return _stream.DisposeAsync();
    }

    private async ValueTask SendDisconnectMessage(DisconnectReasonCode disconnectReasonCode, string? description)
    {
        lock (_lock)
        {
            if (_connectionState is ConnectionState.PeerDisconnected) // if a disconnect message has been received already, no need to send one
            {
                return;
            }

            if (_connectionState is not ConnectionState.Failed)
            {
                _connectionState = ConnectionState.SelfDisconnectSend;
            }
        }

        using var packet = SshPacketPlaintextBuffer.CreateDefault(false);
        FifoQueueWithPriorityMode.QueueEntry queueEntry = new();

        Disconnect.Build(packet, disconnectReasonCode, description);

        await _writerFifoQueueWithPriorityMode.CloseWithPacket(packet, queueEntry);
    }

    private async ValueTask SetErrorState(Exception exception)
    {
        if (exception == null)
        {
            throw new InvalidOperationException();
        }

        //bool requestCancellation = false;

        bool wasInNonFinalState;

        lock (_lock)
        {
            wasInNonFinalState = (_connectionState & ConnectionState.FinalStateFlag) == 0;

            if (wasInNonFinalState)
            {
                _connectionState = ConnectionState.Failed;
            }

            FirstRelevantException ??= exception;
        }

        //stop reading in any case
        _readCancellationTokenSource.Cancel();

        // try to send a disconnection message if still possible
        var disconnectSendInProgress = false;
        if (wasInNonFinalState && exception is SshException sshException && sshException.DisconnectReason.HasValue)
        {
            try
            {
                await SendDisconnectMessage(sshException.DisconnectReason.Value, null);
                disconnectSendInProgress = true;
            }
            catch
            {
                // if the attempt to send an disconnect message resulted in an exception, ignore it in this case
            }
        }

        //stop writing and everything if the disconnect sent attempt was not successful
        if (!disconnectSendInProgress)
        {
            _writeCancellationTokenSource.Cancel();
            _connectCompletedSource?.TrySetException(exception);
            await _stream.DisposeAsync();
        }
    }

    public async ValueTask<bool> WaitFinish(CancellationToken cancellationToken)
    {
        if (_runTask == null)
        {
            SshExceptionThrowHelper.ConnectNotStarted();
        }
        else
        {
            await _runTask.WaitAsync(cancellationToken);
        }

        lock (_lock)
        {
            if (_connectionState == ConnectionState.Failed)
            {
                return false;
            }
        }

        return true;
    }

    public async ValueTask Kill(CancellationToken cancellationToken = default)
    {
        // as the SshException has not set a disconnect reason code, this will terminate immediately
        await SetErrorState(new SshException(Strings.UserForceAbort));
        await WaitFinish(cancellationToken);
    }

    public async ValueTask<bool> Shutdown(string? description = null, CancellationToken cancellationToken = default)
    {
        await SendDisconnectMessage(DisconnectReasonCode.ByApplication, description);
        return await WaitFinish(cancellationToken);
    }
}
