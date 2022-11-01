using Dragonhill.SlimSSH.Algorithms;
using System.Net.Sockets;

namespace Dragonhill.SlimSSH.IO;

public class TcpSshClientConnection
{
    private readonly IAvailableSshAlgorithms _availableSshAlgorithms;
    private readonly string _host;
    private readonly ushort _port;
    private readonly TcpClient _tcpClient = new();
    private SshTransportOperator? _sshTransportOperator;

    public TcpSshClientConnection(IAvailableSshAlgorithms availableSshAlgorithms, string host, ushort port)
    {
        _availableSshAlgorithms = availableSshAlgorithms;
        _host = host;
        _port = port;
    }

    public async Task Connect(TimeSpan? timeout = null)
    {
        var timeoutTask = timeout != null ? Task.Delay(timeout.Value) : null;
        var connectTask = _tcpClient.ConnectAsync(_host, _port);

        if (timeoutTask != null)
        {
            var firstTask = await Task.WhenAny(connectTask, timeoutTask);

            if (firstTask == timeoutTask)
            {
                _tcpClient.Dispose();
                throw new TimeoutException();
            }
        }

        await connectTask;

        _sshTransportOperator = new SshTransportOperator(_availableSshAlgorithms, _tcpClient.GetStream(), (stream, algorithmContext) => (new SshPacketReader(stream, algorithmContext), new SshPacketWriter(stream, algorithmContext)));
    }

    public async Task TryReadPacket()
    {
        var packet = await _sshTransportOperator!.ReadPacket();
        packet?.Dispose();
    }
}
