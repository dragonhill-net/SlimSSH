namespace Dragonhill.SlimSSH.Algorithms;

public interface ICryptoAlgorithm : IAlgorithmId, IContextAlgorithm
{
    bool ReplacesMacAlgorithm { get; }

    int EffectivePaddingSize { get; }

    int RequiredBytesToDecryptLength { get; }

    void Encrypt(Span<byte> encryptionContext, uint sequenceNumber, ReadOnlySpan<byte> binaryPacketPlaintext, Span<byte> ciphertext);

    uint DecryptLength(Span<byte> decryptionContext, ReadOnlySpan<byte> ciphertext);

    void Decrypt(Span<byte> decryptionContext, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext);
}
