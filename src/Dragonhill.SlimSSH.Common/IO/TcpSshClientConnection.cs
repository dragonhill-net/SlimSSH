using System.Net.Sockets;

namespace Dragonhill.SlimSSH.IO;

public class TcpSshClientConnection : SshConnectionBase
{
    private readonly string _host;
    private readonly ushort _port;
    private readonly TcpClient _tcpClient = new();

    public TcpSshClientConnection(string host, ushort port)
    {
        _host = host;
        _port = port;
    }

    public override async Task Connect(TimeSpan? timeout = null)
    {
        var timeoutTask = timeout != null ? Task.Delay(timeout.Value) : null;
        var connectTask = _tcpClient.ConnectAsync(_host, _port);

        if (timeoutTask != null)
        {
            var firstTask = await Task.WhenAny(connectTask, timeoutTask);

            if (firstTask == timeoutTask)
            {
                Abort();
                throw new TimeoutException();
            }
        }

        await connectTask;

        await StartConnection(_tcpClient.GetStream(), timeoutTask);
    }
}
