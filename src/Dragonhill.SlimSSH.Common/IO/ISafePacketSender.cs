using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.IO;

public delegate void PackageBuilderAction(IAlgorithmKexContext context, ref SshPacketBuilder packetBuilder);

public interface ISafePacketSender
{
    ValueTask GenerateAndSend(PackageBuilderAction builder, int? payloadSize = null);

    ReadOnlySpan<byte> PeerVersionBytesWithoutCrLf { get; }
}
