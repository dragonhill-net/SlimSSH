using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Localization;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading.Channels;

namespace Dragonhill.SlimSSH.IO;

/// <remarks>
/// This class is thread safe after the initialization with <see cref="StartConnection"/>. <see cref="StartConnection"/> must only be called once!
/// </remarks>
public abstract class SshConnectionBase : ISshConnection
{
    private const int TransmissionChannelCapacity = 15;

    private readonly Pipe _pipe = new();
    private readonly Channel<(byte[], int)> _transmissionChannel = Channel.CreateBounded<(byte[], int)>(TransmissionChannelCapacity);
    private Task? _pipeRunnerTask;
    private SshConnectionState _state = SshConnectionState.Unconnected;
    private TaskCompletionSource? _currentStateCompletionSource;

    public bool IsClosed => _pipeRunnerTask?.IsCompleted ?? false;
    public ISshProtocolVersion? ServerVersion { get; private set; }

    public abstract Task Connect(TimeSpan? timeout = null);

    internal void Abort()
    {
        _pipe.Reader.CancelPendingRead();
        _transmissionChannel.Writer.TryComplete();
    }

    private async Task WaitForTaskOrTimeout(Task task, Task? timeoutTask)
    {
        if (timeoutTask != null)
        {
            var firstTask = await Task.WhenAny(task, timeoutTask);

            if (firstTask == timeoutTask)
            {
                Abort();

                throw new TimeoutException();
            }
        }

        await task;
    }

    protected async Task StartConnection(Stream stream, Task? remainingTimeout = null)
    {
        TaskCompletionSource connectionCompletedSource = new();

        // This is just a safeguard to indicate wrong usage, StartConnection must not be called twice!
        if (_state != SshConnectionState.Unconnected)
        {
            throw new SshException(Strings.SshConnectionBase_ConnectCalledTwice);
        }

        _state = SshConnectionState.Connecting;
        _currentStateCompletionSource = connectionCompletedSource;

        _pipeRunnerTask = PipeRunner(stream);

        // Queue the client version as first message to be sent
        await _transmissionChannel.Writer.WriteAsync(SshProtocolVersion.WriteVersion(ArrayPool<byte>.Shared, GitVersionInformation.SemVer));

        try
        {
            await WaitForTaskOrTimeout(connectionCompletedSource.Task, remainingTimeout);
        }
        catch (TaskCanceledException)
        {
            throw new SshException(Strings.SshConnectionBase_ClosedUnexpectedly);
        }
    }

    private async Task PipeRunner(Stream stream)
    {
        try
        {
            var tasks = new List<Task>(3)
                {
                    StreamReader(stream, _pipe.Writer),
                    DataProcessor(_pipe.Reader),
                    DataTransmitter(stream, _transmissionChannel.Reader)
                };

            while (tasks.Count > 0)
            {
                var finishedTask = await Task.WhenAny(tasks);

                // If there was an exception, propagate it
                await finishedTask;

                tasks.Remove(finishedTask);

                // If any of the data handling threads completes without exception also mark the pipe and channel as closed
                await _pipe.Reader.CompleteAsync();
                await _pipe.Writer.CompleteAsync();
                _transmissionChannel.Writer.TryComplete();
            }

            // If there is a wait for the current state to complete, try to cancel it
            var currentStateCompletionSource = _currentStateCompletionSource;
            currentStateCompletionSource?.TrySetCanceled();
        }
        catch(Exception exception)
        {
            // If there is a wait for the current state to complete, also try to propagate the exception there
            var currentStateCompletionSource = _currentStateCompletionSource;
            currentStateCompletionSource?.TrySetException(exception);

            throw;
        }
        finally
        {
            await stream.DisposeAsync();
            await _pipe.Reader.CompleteAsync();
            await _pipe.Writer.CompleteAsync();
            _transmissionChannel.Writer.TryComplete();
        }
    }

    private async Task DataTransmitter(Stream stream, ChannelReader<(byte[], int)> reader)
    {
        var notDraining = true;

        for (;;)
        {
            try
            {
                var (buffer, length) = await reader.ReadAsync();

                if (notDraining)
                {
                    await stream.WriteAsync(buffer, 0, length);
                }

                ArrayPool<byte>.Shared.Return(buffer);
            }
            catch (ChannelClosedException) // No more data available to read, channel is closed
            {
                return;
            }
            catch (ObjectDisposedException) // Stream is disposed, empty the channel to return all unsent messages
            {
                Abort();
                notDraining = false;
            }
        }
    }

    private static async Task StreamReader(Stream stream, PipeWriter pipeWriter)
    {
        for (;;)
        {
            var writerMemory = pipeWriter.GetMemory();

            var bytesRead = await stream.ReadAsync(writerMemory);
            if (bytesRead == 0)
            {
                break;
            }

            pipeWriter.Advance(bytesRead);

            var result = await pipeWriter.FlushAsync();

            if (result.IsCompleted)
            {
                break;
            }
        }

        await pipeWriter.CompleteAsync();
    }

    private async Task DataProcessor(PipeReader pipeReader)
    {
        try
        {
            for (;;)
            {
                var readResult = await pipeReader.ReadAsync();

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

                switch (_state)
                {
                    case SshConnectionState.Connecting:
                        if (SshProtocolVersion.TryReadProtocolVersionExchange(inputBuffer, out consumedRange, out var serverVersion))
                        {
                            ServerVersion = serverVersion;
                            _state = SshConnectionState.ProtocolVersionExchangeDone;
                            var completionSource = _currentStateCompletionSource!;
                            _currentStateCompletionSource = null;
                            completionSource.TrySetResult();
                        }

                        break;

                    default: // TODO: This should be changed to something useful when the protocol has been implemented
                        throw new NotImplementedException();
                }

                if (!consumedRange.HasValue)
                {
                    // Need more data, consumed nothing yet
                    pipeReader.AdvanceTo(inputBuffer.Start, inputBuffer.End);
                }
                else
                {
                    // Tell the pipe reader how much has been consumed so far
                    pipeReader.AdvanceTo(consumedRange.Value);
                }

                if (readResult.IsCompleted)
                {
                    return;
                }
            }
        }
        finally
        {
            await pipeReader.CompleteAsync();
        }
    }

    public Task WaitClose(TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        if (_pipeRunnerTask == null)
        {
            throw new SshException(Strings.SshConnectionBase_NotStarted);
        }

        return WaitForTaskOrTimeout(_pipeRunnerTask, timeout != null ? Task.Delay(timeout.Value, cancellationToken) : null);
    }
}
