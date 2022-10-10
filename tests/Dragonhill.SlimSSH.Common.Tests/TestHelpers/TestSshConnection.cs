using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.IO;
using System;
using System.Buffers;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Dragonhill.SlimSSH.TestHelpers;

public class TestSshConnection : SshConnectionBase
{
    internal MockChunkedStream Stream { get; } = new MockChunkedStream();

    internal const string Version = "1.0-test";
    internal const string Comment = "some test comment";

    public TestSshConnection SendServerVersion(bool? firstHalf = null)
    {
        using var memoryStream = new MemoryStream();
        var (versionBuffer, length) = SshProtocolVersion.WriteVersion(ArrayPool<byte>.Shared, Version, Comment);
        var half = length / 2;
        if (!firstHalf.HasValue || firstHalf.Value)
        {
            Stream.AddReadDataChunk(versionBuffer[..half]);
        }

        if (!firstHalf.HasValue || !firstHalf.Value)
        {
            Stream.AddReadDataChunk(versionBuffer[half..length]);
        }

        ArrayPool<byte>.Shared.Return(versionBuffer);

        return this;
    }

    public TestSshConnection SendInvalidSshVersion()
    {
        var bytes = Encoding.UTF8.GetBytes("SSH-3.0-version\r\n");
        Stream.AddReadDataChunk(bytes);

        return this;
    }

    public override async Task Connect(TimeSpan? timeout = null)
    {
        await StartConnection(Stream, timeout != null ? Task.Delay(timeout.Value) : null);
    }

    public void CloseServer()
    {
        Stream.AddReadDataChunk(Array.Empty<byte>());
    }
}
