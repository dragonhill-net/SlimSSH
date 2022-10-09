
using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Localization;
using System.Buffers;
using System.IO.Pipelines;
using System.Text;

namespace Dragonhill.SlimSSH.IO;

/// <remarks>
/// This class is thread safe after the initialization with <see cref="StartConnection"/>. <see cref="StartConnection"/> must only be called once!
/// </remarks>
public abstract class SshConnectionBase : ISshConnection
{
    private SshConnectionState _state = SshConnectionState.New;

    private Task _pipeRunnerTask;
    private TaskCompletionSource? _initCompletionSource = new();

    public ISshProtocolVersion? ServerVersion { get; private set; }

    public abstract Task Connect();

    protected async Task StartConnection(Stream stream)
    {
        _pipeRunnerTask = PipeRunner(stream);
        await _initCompletionSource!.Task;
    }

    private async Task PipeRunner(Stream stream)
    {
        try
        {
            var pipe = new Pipe();

            var pipeWriterTask = StreamReader(stream, pipe.Writer);
            var pipeReaderTask = DataProcessor(pipe.Reader);

            await Task.WhenAll(pipeWriterTask, pipeReaderTask);
        }
        catch (Exception exception)
        {
            //TODO: do something with the exception
        }
    }

    private async Task StreamReader(Stream stream, PipeWriter pipeWriter)
    {
        var writerMemory = pipeWriter.GetMemory();

        for (;;)
        {
            try
            {
                var bytesRead = await stream.ReadAsync(writerMemory);
                if (bytesRead == 0)
                {
                    break;
                }

                pipeWriter.Advance(bytesRead);
            }
            catch (Exception exception)
            {
                //TODO handle errors
            }

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
        for (;;)
        {
            var readResult = await pipeReader.ReadAsync();
            var inputBuffer = readResult.Buffer;

            do
            {
                SequencePosition? consumedRange;

                switch (_state)
                {
                    case SshConnectionState.New:
                        if (SshProtocolVersion.TryReadProtocolVersionExchange(inputBuffer, out consumedRange, out var serverVersion))
                        {
                            _state = SshConnectionState.ProtocolVersionExchangeDone;
                            _initCompletionSource!.SetResult();
                            _initCompletionSource = null;
                            ServerVersion = serverVersion;
                        }

                        break;

                    // case SshConnectionState.ProtocolVersionExchangeDone:
                    //     break;

                    default:
                        throw new InvalidOperationException();
                }

                if (!consumedRange.HasValue)
                {
                    // Need more data, consumed nothing yet
                    pipeReader.AdvanceTo(inputBuffer.Start, inputBuffer.End);
                    break;
                }

                // Tell the pipe reader how much we consumed so far and set the input buffer to the remainder
                pipeReader.AdvanceTo(consumedRange.Value);
                inputBuffer = inputBuffer.Slice(consumedRange.Value);

            } while (!inputBuffer.IsEmpty);
        }
    }
}
