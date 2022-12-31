namespace Dragonhill.SlimSSH.Algorithms;

public interface ICryptoAlgorithm : IAlgorithmId
{
    bool ReplacesMacAlgorithm { get; }

    int AdditionalCryptoBytes { get; }

    int RequiredContextSize { get; }

    int RequiredInitializationVectorBytes { get; }

    int RequiredKeyBytes { get; }

    void Init(Span<byte> encryptionContext, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> key);

    byte ApplyPadding(Span<byte> paddingArea, int payloadLength);

    int RequiredBytesToDecryptLength { get; }

    void Encrypt(Span<byte> encryptionContext, uint sequenceNumber, ReadOnlySpan<byte> binaryPacketPlaintext, Span<byte> ciphertext);

    /// <remarks>
    /// ATTENTION!
    /// This method may write more than the length (e.g the first decrypted block) to the target buffer (it returns the number of bytes written), so pass at least the number of bytes in the buffer to <see cref="Decrypt"/>!
    /// The required length of the buffer is equal to the <see cref="RequiredBytesToDecryptLength"/>.
    /// </remarks>
    /// <returns>The packet length</returns>
    int DecryptLength(Span<byte> decryptionContext, uint sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext);

    /// <remarks>
    /// ATTENTION!
    /// This method depends on <see cref="DecryptLength"/> being called first (because it may have decrypted the first block or something) => implementation specific.
    /// Just make sure to pass the number of bytes returned by <see cref="DecryptLength"/> at the beginning of <paramref name="plaintext"/>.
    /// </remarks>
    void Decrypt(Span<byte> decryptionContext, uint sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext);

    bool ValidatePayloadAndPaddingLength(int payloadLength, byte paddingAmount);
}
