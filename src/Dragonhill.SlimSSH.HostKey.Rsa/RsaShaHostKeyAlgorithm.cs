using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;
using System.Security.Cryptography;

namespace Dragonhill.SlimSSH.Algorithms;

public abstract class RsaShaHostKeyAlgorithm : IHostKeyAlgorithm
{
    public abstract ReadOnlySpan<byte> IdBytes { get; }

    public bool SupportsSignature => true;

    public bool SupportsEncryption => false;

    protected abstract HashAlgorithmName GetHashAlgorithmName { get; }

    public bool VerifyExchangeHash(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> exchangeHash, ReadOnlySpan<byte> signature)
    {
        var signatureReader = new SshDeserializer(signature);

        if (!signatureReader.ReadBytesString().SequenceEqual(IdBytes))
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_InvalidSignatureFormat);
        }

        var rsaSignatureBlob = signatureReader.ReadBytesString();
        signatureReader.CheckReadEverything();


        var publicKeyReader = new SshDeserializer(publicKey);

        if (!publicKeyReader.ReadBytesString().SequenceEqual(KeyPrefix))
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_InvalidKeyFormat);
        }

        var e = publicKeyReader.ReadMpintAsUnsignedBytes().ToArray();
        var n = publicKeyReader.ReadMpintAsUnsignedBytes().ToArray();
        publicKeyReader.CheckReadEverything();

        var rsa = RSA.Create(new RSAParameters
            {
                Exponent = e,
                Modulus = n
            });

        return rsa.VerifyData(exchangeHash, rsaSignatureBlob, GetHashAlgorithmName, RSASignaturePadding.Pkcs1);
    }

    private static readonly byte[] KeyPrefix =
        {
            (byte)'s',
            (byte)'s',
            (byte)'h',
            (byte)'-',
            (byte)'r',
            (byte)'s',
            (byte)'a'
        };
}
