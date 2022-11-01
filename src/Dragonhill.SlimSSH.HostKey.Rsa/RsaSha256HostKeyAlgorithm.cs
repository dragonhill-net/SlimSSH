using System.Security.Cryptography;

namespace Dragonhill.SlimSSH.Algorithms;

public sealed class RsaSha256HostKeyAlgorithm : RsaShaHostKeyAlgorithm
{
    public override ReadOnlySpan<byte> IdBytes => IdBytesArray;

    protected override HashAlgorithmName GetHashAlgorithmName => HashAlgorithmName.SHA256;

    private static readonly byte[] IdBytesArray =
        {
            (byte)'r',
            (byte)'s',
            (byte)'a',
            (byte)'-',
            (byte)'s',
            (byte)'h',
            (byte)'a',
            (byte)'2',
            (byte)'-',
            (byte)'2',
            (byte)'5',
            (byte)'6'
        };
}
