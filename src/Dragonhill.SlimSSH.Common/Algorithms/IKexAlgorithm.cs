using Dragonhill.SlimSSH.IO;

namespace Dragonhill.SlimSSH.Algorithms;

public interface IKexAlgorithm : IAlgorithmId
{
    bool RequiresSignatureCapableHostKey { get; }
    bool RequiresEncryptionCapableHostKey { get; }

    int HashSizeInBytes { get; }

    void Hash(ReadOnlySpan<byte> data, Span<byte> hash);

    ValueTask StartKex(IAlgorithmKexContext algorithmKexContext, ISafePacketSender safePacketSender);

    ValueTask<bool> FilterPacket(IAlgorithmKexContext algorithmKexContext, byte messageId, ReadOnlyMemory<byte> packetPayload, ISafePacketSender safePacketSender);
}
