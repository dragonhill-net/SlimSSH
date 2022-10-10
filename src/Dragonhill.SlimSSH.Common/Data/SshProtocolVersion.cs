using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.IO;
using Dragonhill.SlimSSH.Localization;
using System.Buffers;
using System.Text;

namespace Dragonhill.SlimSSH.Data;

public class SshProtocolVersion : ISshProtocolVersion
{
    public SshProtocolVersion(string softwareVersion, string? comment)
    {
        SoftwareVersion = softwareVersion;
        Comment = comment;
    }

    public string SoftwareVersion { get; }
    public string? Comment { get; }

    internal static (byte[], int) WriteVersion(ArrayPool<byte> pool, string semVer, string? comment = null)
    {
        var versionString = $"SSH-2.0-{Constants.VersionName}_{semVer.Replace('-', '_')}";
        var versionStringByteCount = Encoding.UTF8.GetByteCount(versionString);

        var totalByteCount = versionStringByteCount + 2 + (comment != null ? 1 + Encoding.UTF8.GetByteCount(comment) : 0);

        var byteBuffer = pool.Rent(totalByteCount);
        var exactByteBufferSpan = byteBuffer.AsSpan(..totalByteCount);

        var len = Encoding.UTF8.GetBytes(versionString, exactByteBufferSpan[..versionStringByteCount]);

        if (comment != null)
        {
            exactByteBufferSpan[versionStringByteCount] = (byte)' ';
            Encoding.UTF8.GetBytes(comment, exactByteBufferSpan[(versionStringByteCount + 1)..^2]);
        }

        exactByteBufferSpan[^2] = (byte)'\r';
        exactByteBufferSpan[^1] = (byte)'\n';

        return (byteBuffer, totalByteCount);
    }

    internal static bool TryReadProtocolVersionExchange(ReadOnlySequence<byte> inputSequence, out SequencePosition? consumedRange, out SshProtocolVersion? version)
    {
        var positionOfLineFeed = inputSequence.PositionOf((byte) '\n');

        if (positionOfLineFeed == null)
        {
            if (inputSequence.Length >= Constants.ProtocolVersionExchangeMaxLineLength)
            {
                throw new SshException(Strings.ProtocolVersionExchange_LineTooLong);
            }

            consumedRange = null;
            version = null;
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
            version = null;
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

        string? serverComment = null;
        if (firstSpace >= 0)
        {
            var commentsBytes = softwareVersionAndCommentsBytes[(firstSpace + 1)..];
            serverComment = Encoding.UTF8.GetString(commentsBytes);
        }

        version = new SshProtocolVersion(serverSoftwareVersion, serverComment);
        consumedRange = inputSequence.GetPosition(1, positionOfLineFeed.Value);
        return true;
    }
}
