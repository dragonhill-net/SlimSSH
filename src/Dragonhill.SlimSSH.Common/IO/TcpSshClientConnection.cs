using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Helpers;
using System.Net.Sockets;

namespace Dragonhill.SlimSSH.IO;

public class TcpSshClientConnection
{
    private readonly IAvailableSshAlgorithms _availableSshAlgorithms;
    private readonly string _host;
    private readonly ushort _port;
    private readonly TcpClient _tcpClient = new();
    private SshTransportStream? _sshTransportStream;

    public SshProtocolVersion? PeerVersion => _sshTransportStream?.PeerVersion;

    public TcpSshClientConnection(IAvailableSshAlgorithms availableSshAlgorithms, string host, ushort port)
    {
        _availableSshAlgorithms = availableSshAlgorithms;
        _host = host;
        _port = port;
    }

    public async Task Connect(CancellationToken cancellationToken = default)
    {
        await _tcpClient.ConnectAsync(_host, _port, cancellationToken);

        _sshTransportStream = new SshTransportStream(_availableSshAlgorithms, _tcpClient.GetStream());

        await _sshTransportStream.Connect(cancellationToken);
    }

    public async Task WaitFinish(CancellationToken cancellationToken = default)
    {
        if (_sshTransportStream == null)
        {
            throw new InvalidOperationException();
        }

        if (!await _sshTransportStream.WaitFinish(cancellationToken))
        {
            throw _sshTransportStream.FirstRelevantException ?? new InvalidOperationException();
        }
    }

    public ValueTask Kill(CancellationToken cancellationToken = default)
    {
        if (_sshTransportStream == null)
        {
            throw new InvalidOperationException();
        }

        return _sshTransportStream.Kill(cancellationToken);
    }

    public ValueTask<bool> Shutdown(string? description = null, CancellationToken cancellationToken = default)
    {
        if (_sshTransportStream == null)
        {
            throw new InvalidOperationException();
        }

        return _sshTransportStream.Shutdown(description, cancellationToken);
    }
}
