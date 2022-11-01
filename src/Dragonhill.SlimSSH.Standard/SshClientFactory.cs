using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.IO;

namespace Dragonhill.SlimSSH;

public static class SshClientFactory
{
    public static TcpSshClientConnection CreateNewTcp(string host, ushort port)
    {
        return new TcpSshClientConnection(StandardAlgorithmSet.Instance, host, port);
    }
}
