using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Collections;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol.Packets;
using System.Runtime.CompilerServices;

namespace Dragonhill.SlimSSH.Protocol;

internal sealed class KexExecutor : IKexContext
{
    private readonly FifoQueueWithPriorityMode.QueueEntry _fifoQueueEntry = new();

    private readonly IAvailableSshAlgorithms _availableSshAlgorithms;
    private readonly AlgorithmContext _algorithmContext;
    private readonly FifoQueueWithPriorityMode _fifoQueue;

    private SpinLock _lock;

    internal SshProtocolVersion? PeerVersion { get; set; }
    private byte[]? _sessionId;

    private bool _kexInitReceived;
    private bool _kexInitSend;

    private SshPacketPlaintextBuffer? _ownKexInit;
    private SshPacketPlaintextBuffer? _peerKexInit;

    private byte[] _kexAlgorithmBuffer;

    private IKexAlgorithm? _kexAlgorithm;
    private IHostKeyAlgorithm? _hostKeyAlgorithm;
    private ICryptoAlgorithm? _clientToServerCryptoAlgorithm;
    private ICryptoAlgorithm? _serverToClientCryptoAlgorithm;
    private IMacAlgorithm? _clientToServerMacAlgorithm;
    private IMacAlgorithm? _serverToClientMacAlgorithm;

    private Memory<byte>? _clientToServerCryptoContext;
    private Memory<byte>? _serverToClientCryptoContext;
    private Memory<byte>? _clientToServerMacContext;
    private Memory<byte>? _serverToClientMacContext;

    private bool _ignoreNextKexPacket;

    public KexExecutor(IAvailableSshAlgorithms availableSshAlgorithms, AlgorithmContext algorithmContext, FifoQueueWithPriorityMode fifoQueue)
    {
        _kexAlgorithmBuffer = Array.Empty<byte>();
        _availableSshAlgorithms = availableSshAlgorithms;
        _algorithmContext = algorithmContext;
        _fifoQueue = fifoQueue;
    }

    Span<byte> IKexContext.KexAlgorithmBuffer => _kexAlgorithmBuffer;

    ReadOnlySpan<byte> IKexContext.OwnKexInitPayload => _ownKexInit!.GetPayloadSpan();

    ReadOnlySpan<byte> IKexContext.PeerKexInitPayload => _peerKexInit!.GetPayloadSpan();

    IKexAlgorithm IKexContext.KexAlgorithm => _kexAlgorithm!;

    IHostKeyAlgorithm IKexContext.HostKeyAlgorithm => _hostKeyAlgorithm!;

    void IKexContext.ResetKexAlgorithmBufferBuffer(int minSize)
    {
        if (_kexAlgorithmBuffer.Length < minSize)
        {
            _kexAlgorithmBuffer = new byte[minSize];
        }
    }

    async ValueTask IKexContext.GenerateAndSend(Action<IKexContext, SshPacketPlaintextBuffer> builder, int? payloadSize)
    {
        using var plaintextBuffer = SshPacketPlaintextBuffer.CreateDefault(true);

        builder(this, plaintextBuffer);
        await _fifoQueue.WriteAsyncPriority(plaintextBuffer, _fifoQueueEntry, true);
    }

    ReadOnlySpan<byte> IKexContext.PeerVersionBytesWithoutCrLf => PeerVersion!.VersionBytesWithoutCrLf;

    private void ExtendKey(int additionalRequiredBytes, Span<byte> extendedKeySourceBuffer, int extendedBufferUsedLength, Span<byte> target)
    {
        while (true)
        {
            _kexAlgorithm!.Hash(extendedKeySourceBuffer[..extendedBufferUsedLength], target);

            if (_kexAlgorithm.HashSizeInBytes >= additionalRequiredBytes)
            {
                return;
            }

            target[.._kexAlgorithm.HashSizeInBytes].CopyTo(extendedKeySourceBuffer[extendedBufferUsedLength..]);
            additionalRequiredBytes -= _kexAlgorithm.HashSizeInBytes;
            extendedBufferUsedLength += _kexAlgorithm.HashSizeInBytes;
            target = target[_kexAlgorithm.HashSizeInBytes..];
        }
    }

    private ReadOnlySpan<byte> DeriveKey(int requiredKeyLength, Span<byte> keySourceBuffer, int kAndHLength, byte xChar, Span<byte> target)
    {
        if (requiredKeyLength == 0)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        keySourceBuffer[kAndHLength] = xChar;

        _kexAlgorithm!.Hash(keySourceBuffer, target);

        if (_kexAlgorithm.HashSizeInBytes < requiredKeyLength)
        {
            Span<byte> extendedKeySourceBuffer = stackalloc byte[kAndHLength + requiredKeyLength]; // this should always be enough room

            keySourceBuffer[..kAndHLength].CopyTo(extendedKeySourceBuffer);
            target[.._kexAlgorithm.HashSizeInBytes].CopyTo(extendedKeySourceBuffer[kAndHLength..]);

            ExtendKey(requiredKeyLength - _kexAlgorithm.HashSizeInBytes, extendedKeySourceBuffer, kAndHLength + _kexAlgorithm.HashSizeInBytes, target[_kexAlgorithm.HashSizeInBytes..]);
        }

        return target[..requiredKeyLength];
    }

    private async ValueTask SendNewKeys()
    {
        using var plaintextBuffer = SshPacketPlaintextBuffer.CreateDefault(true);
        NewKeys.Build(plaintextBuffer);

        await _fifoQueue.WriteAsyncPriority(plaintextBuffer, _fifoQueueEntry, false);
    }

    ValueTask IKexContext.FinishKeyExchange(ReadOnlySpan<byte> k, ReadOnlySpan<byte> h)
    {
        _sessionId ??= h.ToArray();

        var maxSingleKeySize = Math.Max(
            Math.Max(
                Math.Max(_clientToServerCryptoAlgorithm!.RequiredInitializationVectorBytes, _clientToServerCryptoAlgorithm.RequiredKeyBytes),
                Math.Max(_serverToClientCryptoAlgorithm!.RequiredInitializationVectorBytes, _serverToClientCryptoAlgorithm.RequiredKeyBytes)
                ),
            Math.Max(_clientToServerMacAlgorithm!.RequiredKeySize, _serverToClientMacAlgorithm!.RequiredKeySize)
            );

        var firstStepKeySourceSize =
            k.Length
            + 5 //shared secret (unsigned) is converted to mpint
            + h.Length // exchange hash length
            + 1 // the single char
            + _sessionId.Length; // session id length;

        var combinedContextSize = _clientToServerCryptoAlgorithm.RequiredContextSize
            + _serverToClientCryptoAlgorithm.RequiredContextSize
            + _clientToServerMacAlgorithm.RequiredContextSize
            + _serverToClientMacAlgorithm.RequiredContextSize;

        Span<byte> keySourceBuffer = stackalloc byte[firstStepKeySourceSize];

        var combinedContext = new byte[combinedContextSize];

        // Copy K | H to the beginning of the buffer, as every key derivation starts with it
        var kAsMpintLength = SshPrimitives.WriteUnsignedAsMPint(k, keySourceBuffer);
        h.CopyTo(keySourceBuffer[kAsMpintLength..]);
        var kAndHLength = kAsMpintLength + h.Length;
        var kHAndCLength = kAndHLength + 1;
        _sessionId.AsSpan().CopyTo(keySourceBuffer[kHAndCLength..]);

        // as the true length of the key source buffer depends on the mpint conversion, set the span to the actual length (required below)
        keySourceBuffer = keySourceBuffer[..(kHAndCLength + _sessionId.Length)];

        var keyBufferSize = maxSingleKeySize > _kexAlgorithm!.HashSizeInBytes ? (maxSingleKeySize / _kexAlgorithm.HashSizeInBytes + 1) * _kexAlgorithm.HashSizeInBytes : maxSingleKeySize;

        Span<byte> keyA = stackalloc byte[keyBufferSize];
        Span<byte> keyB = stackalloc byte[keyBufferSize];

        // client => server crypto
        var clientToServerIv = DeriveKey(_clientToServerCryptoAlgorithm.RequiredInitializationVectorBytes, keySourceBuffer, kAndHLength, (byte)'A', keyA);
        var clientToServerKey = DeriveKey(_clientToServerCryptoAlgorithm.RequiredKeyBytes, keySourceBuffer, kAndHLength, (byte)'C', keyB);
        var currentContextPos = 0;
        _clientToServerCryptoContext = combinedContext.AsMemory(currentContextPos, _clientToServerCryptoAlgorithm.RequiredContextSize);
        _clientToServerCryptoAlgorithm.Init(_clientToServerCryptoContext.Value.Span, clientToServerIv, clientToServerKey);

        // server => client crypto
        var serverToClientIv = DeriveKey(_serverToClientCryptoAlgorithm.RequiredInitializationVectorBytes, keySourceBuffer, kAndHLength, (byte)'B', keyA);
        var serverToClientKey = DeriveKey(_serverToClientCryptoAlgorithm.RequiredKeyBytes, keySourceBuffer, kAndHLength, (byte)'D', keyB);
        currentContextPos += _clientToServerCryptoAlgorithm.RequiredContextSize;
        _serverToClientCryptoContext = combinedContext.AsMemory(currentContextPos, _serverToClientCryptoAlgorithm.RequiredContextSize);
        _serverToClientCryptoAlgorithm.Init(_serverToClientCryptoContext.Value.Span, serverToClientIv, serverToClientKey);

        // client => server MAC
        var clientToServerMacKey = DeriveKey(_clientToServerMacAlgorithm.RequiredKeySize, keySourceBuffer, kAndHLength, (byte)'E', keyA);
        currentContextPos += _serverToClientCryptoAlgorithm.RequiredContextSize;
        _clientToServerMacContext = combinedContext.AsMemory(currentContextPos, _clientToServerMacAlgorithm.RequiredContextSize);
        _clientToServerMacAlgorithm.Init(_clientToServerMacContext.Value.Span, clientToServerMacKey);

        // server => client MAC
        var serverToClientMacKey = DeriveKey(_serverToClientMacAlgorithm.RequiredKeySize, keySourceBuffer, kAndHLength, (byte)'F', keyA);
        currentContextPos += _clientToServerMacAlgorithm.RequiredContextSize;
        _serverToClientMacContext = combinedContext.AsMemory(currentContextPos, _serverToClientMacAlgorithm.RequiredContextSize);
        _serverToClientMacAlgorithm.Init(_serverToClientMacContext.Value.Span, serverToClientMacKey);

        // clear the key material
        keyA.Clear();
        keyB.Clear();

        _kexAlgorithm = null;
        _hostKeyAlgorithm = null;
        _ownKexInit?.Dispose();
        _ownKexInit = null;
        _peerKexInit?.Dispose();
        _peerKexInit = null;

        return SendNewKeys();
    }

    public ValueTask TryInitKex()
    {
        var lockToken = false;
        var sendKexInit = false;

        try
        {
            _lock.Enter(ref lockToken);

            if (!_kexInitSend)
            {
                sendKexInit = true;
                _kexInitSend = true;
            }
        }
        finally
        {
            if (lockToken)
            {
                _lock.Exit(false);
            }
        }

        return sendKexInit ? SendKexInit(false) : ValueTask.CompletedTask;
    }

    public ValueTask ProcessIncomingKexInit(SshPacketPlaintextBuffer plaintextBuffer)
    {
        var sendKexInit = false;
        var lockToken = false;

        try
        {
            _lock.Enter(ref lockToken);

            if (_kexInitReceived)
            {
                throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Transport_KexInitWhileKexActive);
            }

            if (!_kexInitSend)
            {
                sendKexInit = true;
                _kexInitSend = true;
            }

            _kexInitReceived = true;
        }
        finally
        {
            if (lockToken)
            {
                _lock.Exit(false);
            }
        }

        _peerKexInit = plaintextBuffer.Claim();

        return sendKexInit ? SendKexInit(true) : StartKex();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool ShouldIgnorePacket()
    {
        if (!_ignoreNextKexPacket)
        {
            return false;
        }

        _ignoreNextKexPacket = false;
        return true;

    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool WantsPacket(byte messageId)
    {
        return _kexAlgorithm?.WantsPacket(messageId) ?? false;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask FilterPacket(SshPacketPlaintextBuffer packetPlaintextBuffer)
    {
        return _kexAlgorithm!.HandlePacket(this, packetPlaintextBuffer);
    }

    public void ProcessIncomingNewKeys()
    {
        _algorithmContext.UpdateIncomingAlgorithms(_serverToClientCryptoContext!.Value, _serverToClientCryptoAlgorithm!, _serverToClientMacContext!.Value, _serverToClientMacAlgorithm!);

        _serverToClientCryptoContext = null;
        _serverToClientCryptoAlgorithm = null;
        _serverToClientMacContext = null;
        _serverToClientMacAlgorithm = null;

        CheckKexDone();
    }

    public void ProcessOutgoingNewKeys()
    {
        _algorithmContext.UpdateOutgoingAlgorithms(_clientToServerCryptoContext!.Value, _clientToServerCryptoAlgorithm!, _clientToServerMacContext!.Value, _clientToServerMacAlgorithm!);

        _clientToServerCryptoContext = null;
        _clientToServerCryptoAlgorithm = null;
        _clientToServerMacContext = null;
        _clientToServerMacAlgorithm = null;

        CheckKexDone();
    }

    private void CheckKexDone()
    {
        if (_clientToServerCryptoAlgorithm != null || _serverToClientCryptoAlgorithm != null)
        {
            return;
        }

        var lockToken = false;

        try
        {
            _lock.Enter(ref lockToken);

            _kexInitReceived = _kexInitSend = false;
        }
        finally
        {
            if (lockToken)
            {
                _lock.Exit(false);
            }
        }
    }

    private async ValueTask SendKexInit(bool startKexWhenDone)
    {
        using var plaintextBuffer = SshPacketPlaintextBuffer.CreateDefault(true);

        KexInit.Build(_availableSshAlgorithms, plaintextBuffer);

        await _fifoQueue.WriteAsyncPriority(plaintextBuffer, _fifoQueueEntry, true);

        _ownKexInit = plaintextBuffer.Claim();

        if (startKexWhenDone)
        {
            await StartKex();
        }
    }
    private (IKexAlgorithm, IHostKeyAlgorithm, bool) FindKeyAndHostKeyAlgorithm(ref SshDeserializer deserializer)
    {
        var correctGuess = true;

        var serverKexAlgorithms = deserializer.ReadNameList();
        var serverHostKeyAlgorithms = deserializer.ReadNameList();

        foreach (var clientKexAlgorithm in _availableSshAlgorithms.KexAlgorithms)
        {
            var serverKexAlgorithmIterator = serverKexAlgorithms.GetIterator();
            ReadOnlySpan<byte> serverKexAlgorithm;
            while (!(serverKexAlgorithm = serverKexAlgorithmIterator.NextString()).IsEmpty)
            {
                if (!serverKexAlgorithm.SequenceEqual(clientKexAlgorithm.IdBytes)) // find the first client kex algorithm the server supports
                {
                    correctGuess = false;
                    continue;
                }

                foreach (var clientServerHostKeyAlgorithm in _availableSshAlgorithms.HostKeyAlgorithms)
                {
                    var serverServerHostKeyAlgorithmIterator = serverHostKeyAlgorithms.GetIterator();
                    ReadOnlySpan<byte> serverServerHostKeyAlgorithm;
                    while (!(serverServerHostKeyAlgorithm = serverServerHostKeyAlgorithmIterator.NextString()).IsEmpty)
                    {
                        if (!serverServerHostKeyAlgorithm.SequenceEqual(clientServerHostKeyAlgorithm.IdBytes)) // find the first client server host key algorithm the server supports
                        {
                            continue;
                        }

                        if (clientKexAlgorithm.RequiresSignatureCapableHostKey && !clientServerHostKeyAlgorithm.SupportsSignature)
                        {
                            continue;
                        }

                        if (clientKexAlgorithm.RequiresEncryptionCapableHostKey && !clientServerHostKeyAlgorithm.SupportsEncryption)
                        {
                            continue;
                        }

                        return (clientKexAlgorithm, clientServerHostKeyAlgorithm, correctGuess);
                    }
                }

                correctGuess = false;
            }

            correctGuess = false;
        }

        throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_NoKexAlgorithmMatch);
    }

    private static TAlgorithm FindAlgorithm<TAlgorithm>(IReadOnlyList<TAlgorithm> clientAlgorithms, ref SshDeserializer deserializer, Func<string> errorMessage)
        where TAlgorithm: IAlgorithmId
    {
        var serverAlgorithms = deserializer.ReadNameList();

        foreach (var clientAlgorithm in clientAlgorithms)
        {
            var serverAlgorithmsIterator = serverAlgorithms.GetIterator();
            ReadOnlySpan<byte> serverAlgorithm;
            while (!(serverAlgorithm = serverAlgorithmsIterator.NextString()).IsEmpty)
            {
                if (serverAlgorithm.SequenceEqual(clientAlgorithm.IdBytes))
                {
                    return clientAlgorithm;
                }
            }
        }

        throw new SshException(DisconnectReasonCode.KeyExchangeFailed, errorMessage());
    }

    private static IMacAlgorithm FindMacAlgorithm(IReadOnlyList<IMacAlgorithm> clientAlgorithms, ICryptoAlgorithm cryptoAlgorithm, ref SshDeserializer deserializer, Func<string> errorMessage)
    {
        if (!cryptoAlgorithm.ReplacesMacAlgorithm)
        {
            return FindAlgorithm(clientAlgorithms, ref deserializer, errorMessage);
        }

        deserializer.ReadNameList();
        return NoneMacAlgorithm.Instance;
    }

    private static void EnsureNoneIsSupported(ref SshDeserializer deserializer, Func<string> errorMessage)
    {
        var serverNameList = deserializer.ReadNameList();

        var serverNameListIterator = serverNameList.GetIterator();
        ReadOnlySpan<byte> serverName;
        while (!(serverName = serverNameListIterator.NextString()).IsEmpty)
        {
            if (serverName.SequenceEqual(Constants.NoneBytes.Span))
            {
                return;
            }
        }

        throw new SshException(DisconnectReasonCode.KeyExchangeFailed, errorMessage());
    }

    private ValueTask StartKex()
    {
        var deserializer = _peerKexInit!.GetPayloadDeserializerAfterMessageId();

        deserializer.ReadBytes(16); // cookie

        (_kexAlgorithm, _hostKeyAlgorithm, var correctGuess) = FindKeyAndHostKeyAlgorithm(ref deserializer);

        _clientToServerCryptoAlgorithm = FindAlgorithm(_availableSshAlgorithms.CryptoAlgorithms, ref deserializer, () => Strings.Transport_NoKexCryptoMatch);
        _serverToClientCryptoAlgorithm = FindAlgorithm(_availableSshAlgorithms.CryptoAlgorithms, ref deserializer, () => Strings.Transport_NoKexCryptoMatch);

        _clientToServerMacAlgorithm = FindMacAlgorithm(_availableSshAlgorithms.MacAlgorithms, _clientToServerCryptoAlgorithm, ref deserializer, () => Strings.Transport_NoKexMacMatch);
        _serverToClientMacAlgorithm = FindMacAlgorithm(_availableSshAlgorithms.MacAlgorithms, _serverToClientCryptoAlgorithm, ref deserializer, () => Strings.Transport_NoKexMacMatch);

        EnsureNoneIsSupported(ref deserializer, () => Strings.Transport_NoKexUncompressedSupported); // compression client to server
        EnsureNoneIsSupported(ref deserializer, () => Strings.Transport_NoKexUncompressedSupported); // compression server to client

        // language name list is ignored
        deserializer.ReadNameList();
        deserializer.ReadNameList();

        var firstKexPacketFollows = deserializer.ReadBoolean();

        var reserved = deserializer.ReadUint32();

        if (reserved != 0)
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_ReservedNotZero);
        }

        deserializer.CheckReadEverything();

        _ignoreNextKexPacket = firstKexPacketFollows && !correctGuess;

        return _kexAlgorithm.StartKex(this);
    }
}
