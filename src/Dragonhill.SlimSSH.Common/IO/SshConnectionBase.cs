using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Localization;
using System.IO.Pipelines;

namespace Dragonhill.SlimSSH.IO;

/// <remarks>
/// This class is thread safe after the initialization with <see cref="StartConnection"/>. <see cref="StartConnection"/> must only be called once!
/// </remarks>
public abstract class SshConnectionBase : ISshConnection
{
    private readonly Pipe _pipe = new();
    private Task? _pipeRunnerTask;
    private SshConnectionState _state = SshConnectionState.Unconnected;
    private TaskCompletionSource? _currentStateCompletionSource;

    public bool IsClosed => _pipeRunnerTask?.IsCompleted ?? false;
    public ISshProtocolVersion? ServerVersion { get; private set; }

    public abstract Task Connect(TimeSpan? timeout = null);

    internal void Abort()
    {
        _pipe.Reader.CancelPendingRead();
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
            var pipeWriterTask = StreamReader(stream, _pipe.Writer);
            var pipeReaderTask = DataProcessor(_pipe.Reader);

            var firstTask = await Task.WhenAny(pipeWriterTask, pipeReaderTask);

            // If there was an exception, propagate it
            await firstTask;

            // If not await the other task (possibly propagating an exception)
            await (firstTask != pipeWriterTask ? pipeReaderTask : pipeWriterTask);

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
            await _pipe.Reader.CompleteAsync();
            await _pipe.Writer.CompleteAsync();
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
