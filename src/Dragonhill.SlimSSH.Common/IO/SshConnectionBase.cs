
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

    public string? ServerSoftwareVersion { get; private set; }
    public string? ServerComment { get; private set; }

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
                        if (TryReadProtocolVersionExchange(inputBuffer, out consumedRange))
                        {
                            _state = SshConnectionState.ProtocolVersionExchangeDone;
                            _initCompletionSource!.SetResult();
                            _initCompletionSource = null;
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

    private bool TryReadProtocolVersionExchange(ReadOnlySequence<byte> inputSequence, out SequencePosition? consumedRange)
    {
        var positionOfLineFeed = inputSequence.PositionOf((byte) '\n');

        if (positionOfLineFeed == null)
        {
            if (inputSequence.Length >= Constants.ProtocolVersionExchangeMaxLineLength)
            {
                throw new SshException(Strings.ProtocolVersionExchange_LineTooLong);
            }

            consumedRange = null;
            return false;
        }

        //Get the span of memory representing this line (excluding line feed as it is already verified)
        var lineSequence = inputSequence.Slice(0, positionOfLineFeed.Value);
        var lineLength = lineSequence.Length;

        if (lineLength >= Constants.ProtocolVersionExchangeMaxLineLength)
        {
            throw new SshException(Strings.ProtocolVersionExchange_LineTooLong);
        }

        if (lineLength < 1)
        {
            throw new SshException(Strings.ProtocolVersionExchange_LineInvalid);
        }

        // As a line has a well defined max length (enforced above) it may safely allocated on the stack
        Span<byte> lineBytes = stackalloc byte[(int)lineSequence.Length];
        lineSequence.CopyTo(lineBytes);

        // Check for the carriage return before the line feed
        if (lineBytes[^1] != (byte)'\r')
        {
            throw new SshException(Strings.ProtocolVersionExchange_LineInvalid);
        }

        // Check if the line starts with SSH-, if not the implementation ignores the content as it is not the version string (length at least 'SSH-' + <CR>)
        const int sshMinLength = 4 + 1;
        if (lineLength < sshMinLength || lineBytes[0] != (byte)'S' || lineBytes[1] != (byte)'S' || lineBytes[2] != (byte)'H' || lineBytes[3] != (byte)'-')
        {
            consumedRange = inputSequence.GetPosition(1, positionOfLineFeed.Value);
            return false;
        }

        // Check for a valid protocol version (currently must be "2.0")
        const int sshVersionMinLength = sshMinLength + 3 + 1;
        if (lineLength < sshVersionMinLength || lineBytes[4] != (byte)'2' || lineBytes[5] != (byte)'.' || lineBytes[6] != (byte)'0' || lineBytes[7] != (byte)'-')
        {
            throw new SshException(Strings.ProtocolVersionExchange_InvalidVersion);
        }

        var softwareVersionAndCommentsBytes = lineBytes[(sshVersionMinLength - 1)..^1];
        var firstSpace = softwareVersionAndCommentsBytes.IndexOf((byte)' ');

        var softwareVersionBytes = firstSpace >= 0 ? softwareVersionAndCommentsBytes[..firstSpace] : softwareVersionAndCommentsBytes;

        if (softwareVersionBytes.Length == 0)
        {
            throw new SshException(Strings.ProtocolVersionExchange_InvalidSoftwareVersion);
        }

        if (!StringHelper.TryParseProtocolVersionExchangeString(softwareVersionBytes, out var serverSoftwareVersion))
        {
            throw new SshException(Strings.ProtocolVersionExchange_InvalidSoftwareVersion);
        }
        ServerSoftwareVersion = serverSoftwareVersion;

        if (firstSpace >= 0)
        {
            var commentsBytes = softwareVersionAndCommentsBytes[(firstSpace + 1)..];
            ServerComment = Encoding.ASCII.GetString(commentsBytes);
        }

        consumedRange = inputSequence.GetPosition(1, positionOfLineFeed.Value);
        return true;
    }
}
