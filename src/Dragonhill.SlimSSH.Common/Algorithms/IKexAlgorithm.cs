using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Protocol;

namespace Dragonhill.SlimSSH.Algorithms;

public interface IKexAlgorithm : IAlgorithmId
{
    bool RequiresSignatureCapableHostKey { get; }
    bool RequiresEncryptionCapableHostKey { get; }

    int HashSizeInBytes { get; }

    void Hash(ReadOnlySpan<byte> data, Span<byte> hash);

    ValueTask StartKex(IKexContext kexContext);

    bool WantsPacket(byte messageId);

    ValueTask HandlePacket(IKexContext kexContext, SshPacketPlaintextBuffer packetPlaintextBuffer);
}
