using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;
using System.Buffers;
using System.Text;

namespace Dragonhill.SlimSSH.Helpers;

public class SshProtocolVersion
{
    public static readonly byte[] OwnVersion = GetVersionBytes(GitVersionInformation.SemVer);
    public static ReadOnlySpan<byte> OwnVersionWithoutCrLf => OwnVersion.AsSpan(0, OwnVersion.Length - 2);

    private readonly byte[] _versionBytesWithoutCrLf;
    private readonly int _startOfSoftwareVersion;
    private readonly int? _startOfComment;

    private SshProtocolVersion(byte[] versionBytesWithoutCrLf, int startOfSoftwareVersion, int? startOfComment)
    {
        _versionBytesWithoutCrLf = versionBytesWithoutCrLf;
        _startOfSoftwareVersion = startOfSoftwareVersion;
        _startOfComment = startOfComment;
    }

    public string SoftwareVersion => Encoding.UTF8.GetString(_startOfComment.HasValue ? _versionBytesWithoutCrLf.AsSpan(_startOfSoftwareVersion, _startOfComment.Value - _startOfSoftwareVersion - 1) : _versionBytesWithoutCrLf.AsSpan(_startOfSoftwareVersion));
    public string? Comment => _startOfComment.HasValue ? Encoding.UTF8.GetString(_versionBytesWithoutCrLf.AsSpan(_startOfComment.Value)) : null;
    public ReadOnlySpan<byte> VersionBytesWithoutCrLf => _versionBytesWithoutCrLf;

    private static byte[] GetVersionBytes(string semVer, string? comment = null)
    {
        var versionString = $"SSH-2.0-{Constants.VersionName}_{semVer.Replace('-', '_')}";
        var versionStringByteCount = Encoding.UTF8.GetByteCount(versionString);

        var totalByteCount = versionStringByteCount + 2 + (comment != null ? 1 + Encoding.UTF8.GetByteCount(comment) : 0);

        var byteBuffer = new byte[totalByteCount];
        var exactByteBufferSpan = byteBuffer.AsSpan(..totalByteCount);

        Encoding.UTF8.GetBytes(versionString, exactByteBufferSpan[..versionStringByteCount]);

        if (comment != null)
        {
            exactByteBufferSpan[versionStringByteCount] = (byte)' ';
            Encoding.UTF8.GetBytes(comment, exactByteBufferSpan[(versionStringByteCount + 1)..^2]);
        }

        exactByteBufferSpan[^2] = (byte)'\r';
        exactByteBufferSpan[^1] = (byte)'\n';

        return byteBuffer;
    }

    internal static SshProtocolVersion? TryReadProtocolVersionExchange(ReadOnlySequence<byte> inputSequence, out SequencePosition? consumedRange)
    {
        var positionOfLineFeed = inputSequence.PositionOf((byte) '\n');

        if (positionOfLineFeed == null)
        {
            if (inputSequence.Length >= Constants.ProtocolVersionExchangeMaxLineLength)
            {
                throw new SshException(Strings.ProtocolVersionExchange_LineTooLong);
            }

            consumedRange = null;
            return null;
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
           return null;
        }

        // Check for a valid protocol version (currently must be "2.0")
        const int sshVersionMinLength = sshMinLength + 3 + 1;
        if (lineLength < sshVersionMinLength || lineBytes[4] != (byte)'2' || lineBytes[5] != (byte)'.' || lineBytes[6] != (byte)'0' || lineBytes[7] != (byte)'-')
        {
            throw new SshException(DisconnectReasonCode.ProtocolVersionNotSupported, Strings.ProtocolVersionExchange_InvalidVersion);
        }

        const int softwareVersionOffset = sshVersionMinLength - 1;

        var softwareVersionAndCommentsBytes = lineBytes[softwareVersionOffset..^1];
        var firstSpace = softwareVersionAndCommentsBytes.IndexOf((byte)' ');

        var softwareVersionBytes = firstSpace >= 0 ? softwareVersionAndCommentsBytes[..firstSpace] : softwareVersionAndCommentsBytes;

        if (softwareVersionBytes.Length == 0)
        {
            throw new SshException(Strings.ProtocolVersionExchange_InvalidSoftwareVersion);
        }

        ValidateProtocolVersionExchangeString(softwareVersionBytes);

        var version = new SshProtocolVersion(lineBytes[..^1].ToArray(), softwareVersionOffset, firstSpace > 0 ? firstSpace + 1 : null);
        consumedRange = inputSequence.GetPosition(1, positionOfLineFeed.Value);
        return version;
    }

    private static void ValidateProtocolVersionExchangeString(ReadOnlySpan<byte> input)
    {
        //var str = Encoding.UTF8.GetString(input);

        foreach (var c in input)
        {
            if (c is <= 0x1F or >= 0x7F /*or (byte)'-'*/ or (byte)' ')
            {
                throw new SshException(Strings.ProtocolVersionExchange_InvalidSoftwareVersion);
            }
        }
    }
}
