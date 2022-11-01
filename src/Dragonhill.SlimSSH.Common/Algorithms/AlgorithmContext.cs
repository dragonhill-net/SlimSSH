using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.IO;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;

namespace Dragonhill.SlimSSH.Algorithms;

internal sealed class AlgorithmContext
{
    private readonly ISshTransportOperator _sshTransportOperator;
    private readonly byte[] _contextArray;

    private readonly int _kexAfterBytes;
    private readonly long _kexAfterMilliseconds;

    private int _writtenBytes;
    private int _readBytes;
    private long _nextKexAfterTicks;

    private ICryptoAlgorithm _encryptionAlgorithm;
    private ICryptoAlgorithm _decryptionAlgorithm;
    private IMacAlgorithm _macGenerationAlgorithm;
    private IMacAlgorithm _macValidationAlgorithm;

    private ICryptoAlgorithm? _nextEncryptionAlgorithm;
    private ICryptoAlgorithm? _nextDecryptionAlgorithm;
    private IMacAlgorithm? _nextMacGenerationAlgorithm;
    private IMacAlgorithm? _nextMacValidationAlgorithm;

    public IAvailableSshAlgorithms AvailableSshAlgorithms { get; }

    public AlgorithmContext(IAvailableSshAlgorithms availableSshAlgorithms, ISshTransportOperator sshTransportOperator, int kexAfterBytes = Constants.KexAfterBytes, int kexAfterMilliseconds = Constants.KexAfterMilliseconds)
    {
        AvailableSshAlgorithms = availableSshAlgorithms;
        _sshTransportOperator = sshTransportOperator;

        _kexAfterBytes = kexAfterBytes;
        _kexAfterMilliseconds = kexAfterMilliseconds;

        _nextKexAfterTicks = long.MaxValue; // wait at least for the first key exchange

        // twice the context size to have room for the algorithm in negotiation
        _contextArray = new byte[2 * availableSshAlgorithms.Metrics.TotalContextSize];

        _encryptionAlgorithm = _decryptionAlgorithm = NoneCryptoAlgorithm.Instance;
        _macGenerationAlgorithm = _macValidationAlgorithm = NoneMacAlgorithm.Instance;
    }

    public ValueTask OnPacketRead(ReadOnlySpan<byte> packetPlaintext, out bool stopReceiving)
    {
        _readBytes += packetPlaintext.Length + _macValidationAlgorithm.MacLength;

        switch (packetPlaintext[PacketConstants.MessageIdOffset])
        {
            case (byte)MessageId.NewKeys:
                ActivateNextReadAlgorithms();
                break;

            case (byte)MessageId.Disconnect:
                stopReceiving = true;
                return ValueTask.CompletedTask;
        }

        stopReceiving = false;

        if (_readBytes > _kexAfterBytes || Environment.TickCount64 >= _nextKexAfterTicks)
        {
            return _sshTransportOperator.RequestKeyExchange();
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask OnPacketWrite(Span<byte> packetPlaintext, out bool stopSending)
    {
        _writtenBytes += packetPlaintext.Length + _macGenerationAlgorithm.MacLength;

        switch (packetPlaintext[PacketConstants.MessageIdOffset])
        {
            case (byte)MessageId.NewKeys:
                ActivateNextWriteAlgorithms();
                break;

            case (byte)MessageId.Disconnect:
                stopSending = true;
                return ValueTask.CompletedTask;
        }

        stopSending = false;

        if (_writtenBytes > _kexAfterBytes || Environment.TickCount64 >= _nextKexAfterTicks)
        {
            return _sshTransportOperator.RequestKeyExchange();
        }

        return ValueTask.CompletedTask;
    }

    private void ActivateNextReadAlgorithms()
    {
        if (_nextDecryptionAlgorithm == null || _nextMacValidationAlgorithm == null)
        {
            throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Transport_UnexpectedNewKeys);
        }

        _decryptionAlgorithm = _nextDecryptionAlgorithm;
        _macValidationAlgorithm = _nextMacValidationAlgorithm;

        _nextDecryptionAlgorithm = null;
        _nextMacValidationAlgorithm = null;

        _readBytes = 0;
    }

    private void ActivateNextWriteAlgorithms()
    {
        if (_nextEncryptionAlgorithm == null || _nextMacGenerationAlgorithm == null)
        {
            throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Transport_UnexpectedNewKeys);
        }

        _encryptionAlgorithm = _nextEncryptionAlgorithm;
        _macGenerationAlgorithm = _nextMacGenerationAlgorithm;

        _nextEncryptionAlgorithm = null;
        _nextMacGenerationAlgorithm = null;

        _writtenBytes = 0;
    }

    public int EncryptionEffectivePaddingSize => _encryptionAlgorithm.EffectivePaddingSize;

    public void Encrypt(uint sequenceNumber, ReadOnlySpan<byte> binaryPacketPlaintext, Span<byte> ciphertext)
    {
        _encryptionAlgorithm.Encrypt(_contextArray.AsSpan(AvailableSshAlgorithms.Metrics.EncryptionContextOffset, _encryptionAlgorithm.ContextSize), sequenceNumber, binaryPacketPlaintext, ciphertext);
    }


    public int RequiredBytesToDecryptLength => _decryptionAlgorithm.RequiredBytesToDecryptLength;

    public uint DecryptLength(ReadOnlySpan<byte> ciphertext)
    {
        return _encryptionAlgorithm.DecryptLength(_contextArray.AsSpan(AvailableSshAlgorithms.Metrics.DecryptionContextOffset, _decryptionAlgorithm.ContextSize), ciphertext);
    }

    public void Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        _encryptionAlgorithm.Decrypt(_contextArray.AsSpan(AvailableSshAlgorithms.Metrics.DecryptionContextOffset, _decryptionAlgorithm.ContextSize), ciphertext, plaintext);
    }


    public int MacValidationLength => _macValidationAlgorithm.MacLength;

    public bool ValidateMac(ReadOnlySpan<byte> sequenceNumberAndPacketPlaintext, ReadOnlySpan<byte> mac)
    {
        return _macValidationAlgorithm.Validate(_contextArray.AsSpan(AvailableSshAlgorithms.Metrics.MacValidationContextOffset, _macValidationAlgorithm.ContextSize), sequenceNumberAndPacketPlaintext, mac);
    }


    public int MacGenerationLength => _macGenerationAlgorithm.MacLength;

    public void GenerateMac(ReadOnlySpan<byte> sequenceNumberAndPacketPlaintext, Span<byte> mac)
    {
        _macGenerationAlgorithm.Generate(_contextArray.AsSpan(AvailableSshAlgorithms.Metrics.MacGenerationContextOffset, _macGenerationAlgorithm.ContextSize), sequenceNumberAndPacketPlaintext, mac);
    }
}
