namespace Dragonhill.SlimSSH.Algorithms;

public interface IAlgorithmKexContext
{
    bool ShouldIgnoreThisKexPacket();
    IMacAlgorithm? ServerToClientMacAlgorithm { get; }
    IKexAlgorithm? KexAlgorithm { get; }
    IHostKeyAlgorithm? HostKeyAlgorithm { get; }
    ICryptoAlgorithm? ClientToServerCryptoAlgorithm { get; }
    ICryptoAlgorithm? ServerToClientCryptoAlgorithm { get; }
    IMacAlgorithm? ClientToServerMacAlgorithm { get; }

    void NewKexAlgorithmContextBuffer(int minSize);
    Span<byte> GetKexAlgorithmContextBuffer();
    ReadOnlySpan<byte> GetOwnKexInitPacketPayload();
    ReadOnlySpan<byte> GetPeerKexInitPacketPayload();
}
