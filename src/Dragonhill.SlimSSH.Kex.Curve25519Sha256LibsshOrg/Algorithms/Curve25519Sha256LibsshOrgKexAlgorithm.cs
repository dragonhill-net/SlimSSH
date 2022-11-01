using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.IO;
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

    public ValueTask StartKex(IAlgorithmKexContext algorithmKexContext, ISafePacketSender safePacketSender)
    {
        algorithmKexContext.NewKexAlgorithmContextBuffer(KeyAgreementAlgorithm.X25519.PrivateKeySize);
        return safePacketSender.GenerateAndSend(StartKexPacketBuilder);
    }

    private static void StartKexPacketBuilder(IAlgorithmKexContext context, ref SshPacketBuilder packetBuilder)
    {
        var parameters = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving };

        using var key = Key.Create(KeyAgreementAlgorithm.X25519, parameters);

        Span<byte> publicKeyBytes = stackalloc byte[KeyAgreementAlgorithm.X25519.PublicKeySize];
        if (!key.PublicKey.TryExport(KeyBlobFormat.RawPublicKey, publicKeyBytes, out var publicKeyBlobSize) || publicKeyBlobSize != KeyAgreementAlgorithm.X25519.PublicKeySize)
        {
            throw new InvalidOperationException("Public key export error");
        }

        packetBuilder.WriteByte((byte)Curve25519Sha256LibsshOrgMessageIds.KexEcdhInit);
        packetBuilder.WriteBytesString(publicKeyBytes);

        if (!key.TryExport(KeyBlobFormat.RawPrivateKey, context.GetKexAlgorithmContextBuffer(), out var privateKeyBlobSize) || privateKeyBlobSize != KeyAgreementAlgorithm.X25519.PrivateKeySize)
        {
            throw new InvalidOperationException("Private key export error");
        }
    }

    public async ValueTask<bool> FilterPacket(IAlgorithmKexContext algorithmKexContext, byte messageId, ReadOnlyMemory<byte> packetPayload, ISafePacketSender safePacketSender)
    {
        switch (messageId)
        {
            case (byte)Curve25519Sha256LibsshOrgMessageIds.KexEcdhReply:
                await HandleKexEcdhReply(algorithmKexContext, packetPayload, safePacketSender);
                return true;
            default:
                return false;
        }
    }

    private static ValueTask HandleKexEcdhReply(IAlgorithmKexContext algorithmKexContext, ReadOnlyMemory<byte> packetPayload, ISafePacketSender safePacketSender)
    {
        var deserializer = new SshPacketDeserializer(packetPayload.Span);
        deserializer.ReadByte(); // message id
        var serverPublicHostKey = deserializer.ReadBytesString();
        var serverEphemeralPublicKeyBytes = deserializer.ReadBytesString();
        var exchangeHashSignature = deserializer.ReadBytesString();
        deserializer.CheckReadEverything();

        var serverEphemeralPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, serverEphemeralPublicKeyBytes, KeyBlobFormat.RawPublicKey);
        using var clientEphemeralPrivateKey = Key.Import(KeyAgreementAlgorithm.X25519, algorithmKexContext.GetKexAlgorithmContextBuffer(), KeyBlobFormat.RawPrivateKey);

        var sharedSecretCreationParameters = new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving };

        using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(clientEphemeralPrivateKey, serverEphemeralPublicKey, sharedSecretCreationParameters);

        if (sharedSecret == null)
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_KexCouldNotCreateSharedSecret);
        }

        // compute exchange hash
        var ownVersion = SshProtocolVersion.OwnVersionWithoutCrLf;
        var serverVersion = safePacketSender.PeerVersionBytesWithoutCrLf;
        var clientKexInitPayload = algorithmKexContext.GetOwnKexInitPacketPayload();
        var serverKexInitPayload = algorithmKexContext.GetPeerKexInitPacketPayload();

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

        using var hashBuilder = new SshPacketBuilder(exchangeHashBaseLength);
        hashBuilder.WriteBytesString(ownVersion);
        hashBuilder.WriteBytesString(serverVersion);
        hashBuilder.WriteBytesString(clientKexInitPayload);
        hashBuilder.WriteBytesString(serverKexInitPayload);
        hashBuilder.WriteBytesString(serverPublicHostKey);
        hashBuilder.WriteBytesString(clientEphemeralPublicKeyBytes);
        hashBuilder.WriteBytesString(serverEphemeralPublicKeyBytes);
        hashBuilder.WriteUnsignedAsMPint(sharedSecretBytes);

        var hashBaseBytes = hashBuilder.GetPayloadSpan();

        var kexAlgorithm = algorithmKexContext.KexAlgorithm!;

        Span<byte> exchangeHash = stackalloc byte[kexAlgorithm.HashSizeInBytes];

        kexAlgorithm.Hash(hashBaseBytes, exchangeHash);

        var verificationResult = algorithmKexContext.HostKeyAlgorithm!.VerifyExchangeHash(serverPublicHostKey, exchangeHash, exchangeHashSignature);

        if (!verificationResult)
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_SignatureVerificationFailed);
        }

        return ValueTask.CompletedTask;
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
