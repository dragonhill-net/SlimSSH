using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.IO;

internal interface ISshPacketEventHandler
{
    void OnProtocolVersionRead(SshProtocolVersion sshProtocolVersion);

    ValueTask OnPacketReceived(SshPacketPlaintextBuffer plaintextBuffer, int totalBytes);

    ValueTask OnAfterPacketSend(SshPacketPlaintextBuffer plaintextBuffer, int totalBytes);
}
