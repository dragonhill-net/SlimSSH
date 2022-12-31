using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;
using NSec.Cryptography;

namespace Dragonhill.SlimSSH.Algorithms;

/// <summary>
/// For reference: RFC 8709
/// </summary>
public class Ed25519HostKeyAlgorithm : IHostKeyAlgorithm
{
    public ReadOnlySpan<byte> IdBytes => IdBytesArray;

    public bool SupportsSignature => true;

    public bool SupportsEncryption => false;

    public bool VerifyExchangeHash(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> exchangeHash, ReadOnlySpan<byte> signature)
    {
        var publicKeyReader = new SshDeserializer(publicKey);

        if (!publicKeyReader.ReadBytesString().SequenceEqual(IdBytesArray))
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_InvalidKeyFormat);
        }

        var publicKeyBytes = publicKeyReader.ReadBytesString();
        publicKeyReader.CheckReadEverything();


        var signatureReader = new SshDeserializer(signature);

        if (!signatureReader.ReadBytesString().SequenceEqual(IdBytesArray))
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_InvalidSignatureFormat);
        }

        var signatureBytes = signatureReader.ReadBytesString();
        signatureReader.CheckReadEverything();


        var parsedPublicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, publicKeyBytes, KeyBlobFormat.RawPublicKey);

        return SignatureAlgorithm.Ed25519.Verify(parsedPublicKey, exchangeHash, signatureBytes);
    }

    private static readonly byte[] IdBytesArray =
        {
            (byte)'s',
            (byte)'s',
            (byte)'h',
            (byte)'-',
            (byte)'e',
            (byte)'d',
            (byte)'2',
            (byte)'5',
            (byte)'5',
            (byte)'1',
            (byte)'9'
        };
}
