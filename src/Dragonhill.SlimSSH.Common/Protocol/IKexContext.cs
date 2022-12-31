using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.Protocol;

public interface IKexContext
{
    Span<byte> KexAlgorithmBuffer { get; }

    ReadOnlySpan<byte> OwnKexInitPayload { get; }
    ReadOnlySpan<byte> PeerKexInitPayload { get; }

    IKexAlgorithm KexAlgorithm { get; }
    IHostKeyAlgorithm HostKeyAlgorithm { get; }


    void ResetKexAlgorithmBufferBuffer(int minSize);

    ValueTask GenerateAndSend(Action<IKexContext, SshPacketPlaintextBuffer> builder, int? payloadSize = null);

    ReadOnlySpan<byte> PeerVersionBytesWithoutCrLf { get; }

    ValueTask FinishKeyExchange(ReadOnlySpan<byte> k, ReadOnlySpan<byte> h);
}
