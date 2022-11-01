namespace Dragonhill.SlimSSH.Algorithms;

public interface IHostKeyAlgorithm : IAlgorithmId
{
    bool SupportsSignature { get; }
    bool SupportsEncryption { get; }

    bool VerifyExchangeHash(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> exchangeHash, ReadOnlySpan<byte> signature);
}
