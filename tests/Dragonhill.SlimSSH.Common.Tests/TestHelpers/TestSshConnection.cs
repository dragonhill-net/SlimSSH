using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.IO;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Dragonhill.SlimSSH.TestHelpers;

public class TestSshConnection : SshConnectionBase
{
    private readonly MockChunkedStream _stream = new MockChunkedStream();

    internal const string Version = "1.0-test";
    internal const string Comment = "some test comment";

    public TestSshConnection SendServerVersion(bool? firstHalf = null)
    {
        using var memoryStream = new MemoryStream();
        SshProtocolVersion.WriteVersion(memoryStream, Version, Comment);
        var versionBuffer = memoryStream.ToArray();
        var half = versionBuffer.Length / 2;
        if (!firstHalf.HasValue || firstHalf.Value)
        {
            _stream.AddReadDataChunk(versionBuffer[..half]);
        }

        if (!firstHalf.HasValue || !firstHalf.Value)
        {
            _stream.AddReadDataChunk(versionBuffer[half..]);
        }

        return this;
    }

    public TestSshConnection SendInvalidSshVersion()
    {
        var bytes = Encoding.UTF8.GetBytes("SSH-3.0-version\r\n");
        _stream.AddReadDataChunk(bytes);

        return this;
    }

    public override async Task Connect(TimeSpan? timeout = null)
    {
        await StartConnection(_stream, timeout != null ? Task.Delay(timeout.Value) : null);
    }

    public void CloseServer()
    {
        _stream.AddReadDataChunk(Array.Empty<byte>());
    }
}
