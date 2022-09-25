using System.Net.Sockets;

namespace Dragonhill.SlimSSH.IO;

public class TcpSshClientConnection : SshConnectionBase
{
    private readonly string _host;
    private readonly ushort _port;
    private readonly TcpClient _tcpClient = new TcpClient();

    public TcpSshClientConnection(string host, ushort port)
    {
        _host = host;
        _port = port;
    }

    public override async Task Connect()
    {
        await _tcpClient.ConnectAsync(_host, _port);
        await StartConnection(_tcpClient.GetStream());
    }
}
