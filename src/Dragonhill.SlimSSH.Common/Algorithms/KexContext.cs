using Dragonhill.SlimSSH.Helpers;
using System.Buffers;

namespace Dragonhill.SlimSSH.Algorithms;

internal sealed class KexContext : IAlgorithmKexContext
{
    private bool _ignoreNextPacket;
    private SshPacketBuilder? _ownKexInitPacket;
    private PooledBufferWrapper? _peerKexInitPacket;
    private byte[]? _kexAlgorithmContextBuffer;

    public IKexAlgorithm? KexAlgorithm { get; private set; }
    public IHostKeyAlgorithm? HostKeyAlgorithm { get; private set; }
    public ICryptoAlgorithm? ClientToServerCryptoAlgorithm { get; private set; }
    public ICryptoAlgorithm? ServerToClientCryptoAlgorithm { get; private set; }
    public IMacAlgorithm? ClientToServerMacAlgorithm { get; private set; }

    public void NewKexAlgorithmContextBuffer(int minSize)
    {
        ClearKexAlgorithmContextBuffer();
        _kexAlgorithmContextBuffer = ArrayPool<byte>.Shared.Rent(minSize);
    }

    public Span<byte> GetKexAlgorithmContextBuffer()
    {
        return _kexAlgorithmContextBuffer.AsSpan();
    }

    public IMacAlgorithm? ServerToClientMacAlgorithm { get; private set; }

    internal void SetOwnKexInit(SshPacketBuilder ownKexInitPacket)
    {
        _ownKexInitPacket = ownKexInitPacket;
    }

    internal void SetPeerKexInit(PooledBufferWrapper peerKexInitPacket)
    {
        _peerKexInitPacket = peerKexInitPacket;
    }

    internal void SetAlgorithms(IKexAlgorithm kexAlgorithm, IHostKeyAlgorithm hostKeyAlgorithm, ICryptoAlgorithm clientToServerCryptoAlgorithm, ICryptoAlgorithm serverToClientCryptoAlgorithm, IMacAlgorithm clientToServerMacAlgorithm, IMacAlgorithm serverToClientMacAlgorithm)
    {
        KexAlgorithm = kexAlgorithm;
        HostKeyAlgorithm = hostKeyAlgorithm;
        ClientToServerCryptoAlgorithm = clientToServerCryptoAlgorithm;
        ServerToClientCryptoAlgorithm = serverToClientCryptoAlgorithm;
        ClientToServerMacAlgorithm = clientToServerMacAlgorithm;
        ServerToClientMacAlgorithm = serverToClientMacAlgorithm;
    }

    internal void SetIgnoreNextKexPacket()
    {
        _ignoreNextPacket = true;
    }

    public bool ShouldIgnoreThisKexPacket()
    {
        var retval = _ignoreNextPacket;
        _ignoreNextPacket = false;
        return retval;
    }

    public ReadOnlySpan<byte> GetOwnKexInitPacketPayload()
    {
        return _ownKexInitPacket!.Value.GetPayloadSpan();
    }

    public ReadOnlySpan<byte> GetPeerKexInitPacketPayload()
    {
        return _peerKexInitPacket!.Value.GetPayloadSpan();
    }

    private void ClearKexAlgorithmContextBuffer()
    {
        if (_kexAlgorithmContextBuffer == null)
        {
            return;
        }

        ArrayPool<byte>.Shared.Return(_kexAlgorithmContextBuffer, true);
        _kexAlgorithmContextBuffer = null;
    }

    internal void Reset()
    {
        _ignoreNextPacket = false;

        _ownKexInitPacket?.Dispose();
        _ownKexInitPacket = null;

        _peerKexInitPacket?.Dispose();
        _peerKexInitPacket = null;

        ClearKexAlgorithmContextBuffer();

        KexAlgorithm = null;
        HostKeyAlgorithm = null;
        ClientToServerCryptoAlgorithm = null;
        ServerToClientCryptoAlgorithm = null;
        ClientToServerMacAlgorithm = null;
        ServerToClientMacAlgorithm = null;
    }
}
