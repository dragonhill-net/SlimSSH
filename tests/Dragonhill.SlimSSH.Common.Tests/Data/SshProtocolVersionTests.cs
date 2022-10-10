using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Localization;
using FluentAssertions;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace Dragonhill.SlimSSH.Data;

public class SshProtocolVersionTests
{
    private static byte[] CrLfBytes = new[]
        {
            (byte)'\r',
            (byte)'\n'
        };

    [Fact]
    public void WriteVersion_WithComment()
    {
        using var memoryStream = new MemoryStream();
        const string version = "0.1.2-pre+12345";
        const string comment = "This is some comment containing some spaces";

        var (resultBytes, resultLength) = SshProtocolVersion.WriteVersion(ArrayPool<byte>.Shared, version, comment);

        var resultString = Encoding.UTF8.GetString(resultBytes, 0, resultLength);

        var expectedString = $"SSH-2.0-{Constants.VersionName}_{version.Replace('-', '_')} {comment}\r\n";

        resultString.Should().Be(expectedString);

        ArrayPool<byte>.Shared.Return(resultBytes);
    }

    [Fact]
    public void WriteVersion_WithoutComment()
    {
        using var memoryStream = new MemoryStream();
        const string version = "104.272.43";

        var (resultBytes, resultLength) = SshProtocolVersion.WriteVersion(ArrayPool<byte>.Shared, version);

        var resultString = Encoding.UTF8.GetString(resultBytes, 0, resultLength);

        var expectedString = $"SSH-2.0-{Constants.VersionName}_{version.Replace('-', '_')}\r\n";

        resultString.Should().Be(expectedString);

        ArrayPool<byte>.Shared.Return(resultBytes);
    }

    [Fact]
    public void TryReadProtocolVersionExchange_EmptyInput()
    {
        var input = new ReadOnlySequence<byte>();
        SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version);

        consumed.Should().BeNull();
        version.Should().BeNull();
    }

    [Fact]
    public void TryReadProtocolVersionExchange_LineTooLongNoLinefeed()
    {
        var input = new ReadOnlySequence<byte>(Enumerable.Repeat((byte)'X', (int)(Constants.ProtocolVersionExchangeMaxLineLength + 1)).ToArray());

        FluentActions.Invoking(() => SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version))
            .Should()
            .Throw<SshException>()
            .WithMessage(Strings.ProtocolVersionExchange_LineTooLong);
    }

    [Fact]
    public void TryReadProtocolVersionExchange_LineTooLongWithLinefeed()
    {
        var input = new ReadOnlySequence<byte>(Enumerable.Repeat((byte)'X', (int)(Constants.ProtocolVersionExchangeMaxLineLength + 1)).Concat(CrLfBytes).ToArray());
        FluentActions.Invoking(() => SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version))
            .Should()
            .Throw<SshException>()
            .WithMessage(Strings.ProtocolVersionExchange_LineTooLong);
    }

    [Fact]
    public void TryReadProtocolVersionExchange_LineWithoutCrBeforeLf()
    {
        var input = new ReadOnlySequence<byte>(new[] { (byte)'\n' });

        FluentActions.Invoking(() => SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version))
            .Should()
            .Throw<SshException>()
            .WithMessage(Strings.ProtocolVersionExchange_LineInvalid);
    }

    [Fact]
    public void TryReadProtocolVersionExchange_MissingCr()
    {
        var input = new ReadOnlySequence<byte>(new[]
            {
                (byte)'X',
                (byte)'\n'
            });

        FluentActions.Invoking(() => SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version))
            .Should()
            .Throw<SshException>()
            .WithMessage(Strings.ProtocolVersionExchange_LineInvalid);
    }

    [Fact]
    public void TryReadProtocolVersionExchange_AdditionalOtherLines()
    {
        var testLines = new[]
            {
                "SSH\r\n", // Just SSH without the - should be valid for the other lines
                "This is some line not starting with SSH-\r\n"
            };

        foreach (var testLine in testLines)
        {
            var input = new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(testLine));

            SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version);

            consumed.Should().NotBeNull();
            version.Should().BeNull();

            consumed!.Value.GetInteger().Should().Be(testLine.Length);
        }
    }

    [Fact]
    public void TryReadProtocolVersionExchange_InvalidSshVersion()
    {
        var input = new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes("SSH-3.0-test\r\n"));

        FluentActions.Invoking(() => SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version))
            .Should()
            .Throw<SshException>()
            .WithMessage(Strings.ProtocolVersionExchange_InvalidVersion);
    }

    [Fact]
    public void TryReadProtocolVersionExchange_EmptySoftwareVersion()
    {
        var input = new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes("SSH-2.0-\r\n"));

        FluentActions.Invoking(() => SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version))
            .Should()
            .Throw<SshException>()
            .WithMessage(Strings.ProtocolVersionExchange_InvalidSoftwareVersion);
    }

    [Fact]
    public void TryReadProtocolVersionExchange_InvalidSoftwareVersion()
    {
        var input = new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes("SSH-2.0-test_1.0-pre\r\n"));

        FluentActions.Invoking(() => SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version))
            .Should()
            .Throw<SshException>()
            .WithMessage(Strings.ProtocolVersionExchange_InvalidSoftwareVersion);
    }

    [Fact]
    public void TryReadProtocolVersionExchange_ValidVersionWithoutComment()
    {
        const string versionString = "valid_version_1.0";
        const string inputString = $"SSH-2.0-{versionString}\r\n";
        var input = new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(inputString));

        SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version);

        consumed.Should().NotBeNull();
        version.Should().NotBeNull();

        consumed!.Value.GetInteger().Should().Be(inputString.Length);
        version!.SoftwareVersion.Should().Be(versionString);
        version!.Comment.Should().BeNull();
    }



    [Fact]
    public void TryReadProtocolVersionExchange_ValidVersionWithComment()
    {
        const string versionString = "valid_version_1.0";
        const string commentString = "Some comment";
        const string inputString = $"SSH-2.0-{versionString} {commentString}\r\n";
        var input = new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(inputString));

        SshProtocolVersion.TryReadProtocolVersionExchange(input, out var consumed, out var version);

        consumed.Should().NotBeNull();
        version.Should().NotBeNull();

        consumed!.Value.GetInteger().Should().Be(inputString.Length);
        version!.SoftwareVersion.Should().Be(versionString);
        version!.Comment.Should().Be(commentString);
    }
}
