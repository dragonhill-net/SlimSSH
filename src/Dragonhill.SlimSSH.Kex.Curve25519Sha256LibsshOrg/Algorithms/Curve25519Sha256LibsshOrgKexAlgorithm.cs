using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;
using NSec.Cryptography;
using System.Security.Cryptography;

namespace Dragonhill.SlimSSH.Algorithms;

public sealed class Curve25519Sha256LibsshOrgKexAlgorithm : IKexAlgorithm
{
    public ReadOnlySpan<byte> IdBytes => IdBytesArray;

    public bool RequiresSignatureCapableHostKey => true;

    public bool RequiresEncryptionCapableHostKey => false;

    public int HashSizeInBytes => 32;

    public void Hash(ReadOnlySpan<byte> data, Span<byte> hash)
    {
        SHA256.HashData(data, hash);
    }

    public ValueTask StartKex(IKexContext kexContext)
    {
        kexContext.ResetKexAlgorithmBufferBuffer(KeyAgreementAlgorithm.X25519.PrivateKeySize);
        return kexContext.GenerateAndSend(StartKexPacketBuilder);
    }

    public bool WantsPacket(byte messageId) => messageId == (byte)Curve25519Sha256LibsshOrgMessageIds.KexEcdhReply;

    public ValueTask HandlePacket(IKexContext algorithmKexContext, SshPacketPlaintextBuffer packetPlaintextBuffer)
    {
        if (packetPlaintextBuffer.MessageId != (byte)Curve25519Sha256LibsshOrgMessageIds.KexEcdhReply)
        {
            throw new SshException(Strings.Transport_UnexpectedPacket);
        }

        return HandleKexEcdhReply(algorithmKexContext, packetPlaintextBuffer);
    }

    private static void StartKexPacketBuilder(IKexContext kexContext, SshPacketPlaintextBuffer plaintextBuffer)
    {
        var parameters = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving };

        using var key = Key.Create(KeyAgreementAlgorithm.X25519, parameters);

        Span<byte> publicKeyBytes = stackalloc byte[KeyAgreementAlgorithm.X25519.PublicKeySize];
        if (!key.PublicKey.TryExport(KeyBlobFormat.RawPublicKey, publicKeyBytes, out var publicKeyBlobSize) || publicKeyBlobSize != KeyAgreementAlgorithm.X25519.PublicKeySize)
        {
            throw new InvalidOperationException("Public key export error");
        }

        var packetBuilder = new SshSerializer(ref plaintextBuffer);

        packetBuilder.WriteByte((byte)Curve25519Sha256LibsshOrgMessageIds.KexEcdhInit);
        packetBuilder.WriteBytesString(publicKeyBytes);
        packetBuilder.Finish();

        if (!key.TryExport(KeyBlobFormat.RawPrivateKey, kexContext.KexAlgorithmBuffer, out var privateKeyBlobSize) || privateKeyBlobSize != KeyAgreementAlgorithm.X25519.PrivateKeySize)
        {
            throw new InvalidOperationException("Private key export error");
        }
    }

    private static ValueTask HandleKexEcdhReply(IKexContext kexContext, SshPacketPlaintextBuffer packetPlaintextBuffer)
    {
        var deserializer = packetPlaintextBuffer.GetPayloadDeserializerAfterMessageId();
        var serverPublicHostKey = deserializer.ReadBytesString();
        var serverEphemeralPublicKeyBytes = deserializer.ReadBytesString();
        var exchangeHashSignature = deserializer.ReadBytesString();
        deserializer.CheckReadEverything();

        var serverEphemeralPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, serverEphemeralPublicKeyBytes, KeyBlobFormat.RawPublicKey);
        using var clientEphemeralPrivateKey = Key.Import(KeyAgreementAlgorithm.X25519, kexContext.KexAlgorithmBuffer, KeyBlobFormat.RawPrivateKey);

        var sharedSecretCreationParameters = new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving };

        using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(clientEphemeralPrivateKey, serverEphemeralPublicKey, sharedSecretCreationParameters);

        if (sharedSecret == null)
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_KexCouldNotCreateSharedSecret);
        }

        // compute exchange hash
        var ownVersion = SshProtocolVersion.OwnVersionWithoutCrLf;
        var serverVersion = kexContext.PeerVersionBytesWithoutCrLf;
        var clientKexInitPayload = kexContext.OwnKexInitPayload;
        var serverKexInitPayload = kexContext.PeerKexInitPayload;

        Span<byte> clientEphemeralPublicKeyBytes = stackalloc byte[KeyAgreementAlgorithm.X25519.PublicKeySize];
        if (!clientEphemeralPrivateKey.PublicKey.TryExport(KeyBlobFormat.RawPublicKey, clientEphemeralPublicKeyBytes, out var publicKeyBlobSize) || publicKeyBlobSize != KeyAgreementAlgorithm.X25519.PublicKeySize)
        {
            throw new InvalidOperationException("Public key export error");
        }

        Span<byte> sharedSecretBytes = stackalloc byte[sharedSecret.GetExportBlobSize(SharedSecretBlobFormat.RawSharedSecret)];

        if(!sharedSecret.TryExport(SharedSecretBlobFormat.RawSharedSecret, sharedSecretBytes, out _))
        {
            throw new InvalidOperationException("Shared secret export error");
        }

        var exchangeHashBaseLength = 8 * sizeof(uint)
            + ownVersion.Length
            + serverVersion.Length
            + clientKexInitPayload.Length
            + serverKexInitPayload.Length
            + serverPublicHostKey.Length
            + clientEphemeralPublicKeyBytes.Length
            + serverEphemeralPublicKeyBytes.Length
            + sharedSecretBytes.Length + 1; //If the first bit is set need to pad it


        var hashBuilder = new SshSerializer(stackalloc byte[exchangeHashBaseLength]);
        hashBuilder.WriteBytesString(ownVersion);
        hashBuilder.WriteBytesString(serverVersion);
        hashBuilder.WriteBytesString(clientKexInitPayload);
        hashBuilder.WriteBytesString(serverKexInitPayload);
        hashBuilder.WriteBytesString(serverPublicHostKey);
        hashBuilder.WriteBytesString(clientEphemeralPublicKeyBytes);
        hashBuilder.WriteBytesString(serverEphemeralPublicKeyBytes);
        hashBuilder.WriteUnsignedAsMPint(sharedSecretBytes);

        var hashBaseBytes = hashBuilder.Finish();

        var kexAlgorithm = kexContext.KexAlgorithm;

        Span<byte> exchangeHash = stackalloc byte[kexAlgorithm.HashSizeInBytes];

        kexAlgorithm.Hash(hashBaseBytes, exchangeHash);

        var verificationResult = kexContext.HostKeyAlgorithm.VerifyExchangeHash(serverPublicHostKey, exchangeHash, exchangeHashSignature);

        if (!verificationResult)
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_SignatureVerificationFailed);
        }

        return kexContext.FinishKeyExchange(sharedSecretBytes, exchangeHash);
    }

    private static readonly byte[] IdBytesArray =
        {
            (byte)'c',
            (byte)'u',
            (byte)'r',
            (byte)'v',
            (byte)'e',
            (byte)'2',
            (byte)'5',
            (byte)'5',
            (byte)'1',
            (byte)'9',
            (byte)'-',
            (byte)'s',
            (byte)'h',
            (byte)'a',
            (byte)'2',
            (byte)'5',
            (byte)'6',
            (byte)'@',
            (byte)'l',
            (byte)'i',
            (byte)'b',
            (byte)'s',
            (byte)'s',
            (byte)'h',
            (byte)'.',
            (byte)'o',
            (byte)'r',
            (byte)'g'
        };
}
