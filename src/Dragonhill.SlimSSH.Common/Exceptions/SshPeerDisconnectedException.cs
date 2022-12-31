using Dragonhill.SlimSSH.Localization;
using System.Text;

namespace Dragonhill.SlimSSH.Exceptions;

public class SshPeerDisconnectedException : SshException
{
    public uint ReasonCode { get; }
    public string Description { get; }

    public SshPeerDisconnectedException(uint reasonCode, string description)
        : base($"{Strings.Transport_PeerDisconnect}\n\nReason Code: {reasonCode}\n\n{description}")
    {
        ReasonCode = reasonCode;
        Description = description;
    }
}
