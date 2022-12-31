using System.Runtime.CompilerServices;

namespace Dragonhill.SlimSSH.Algorithms;

public class AlgorithmContext
{
    private Memory<byte> _encryptionContext;
    private ICryptoAlgorithm _encryptionAlgorithm;

    private Memory<byte> _macGenerationContext;
    private IMacAlgorithm _macGenerationAlgorithm;

    private Memory<byte> _decryptionContext;
    private ICryptoAlgorithm _decryptionAlgorithm;

    private Memory<byte> _macValidationContext;
    private IMacAlgorithm _macValidationAlgorithm;

    public AlgorithmContext()
    {
        _encryptionContext = Memory<byte>.Empty;
        _encryptionAlgorithm = NoneCryptoAlgorithm.Instance;

        _macGenerationContext = Memory<byte>.Empty;
        _macGenerationAlgorithm = NoneMacAlgorithm.Instance;

        _decryptionContext = Memory<byte>.Empty;
        _decryptionAlgorithm = NoneCryptoAlgorithm.Instance;

        _macValidationContext = Memory<byte>.Empty;
        _macValidationAlgorithm = NoneMacAlgorithm.Instance;
    }

    internal void UpdateIncomingAlgorithms(Memory<byte> decryptionContext, ICryptoAlgorithm decryptionAlgorithm, Memory<byte> macValidationContext, IMacAlgorithm macValidationAlgorithm)
    {
        _decryptionContext.Span.Clear(); // clear the existing key material
        _decryptionContext = decryptionContext;
        _decryptionAlgorithm = decryptionAlgorithm;

        _macValidationContext.Span.Clear(); // clear the existing key material
        _macValidationContext = macValidationContext;
        _macValidationAlgorithm = macValidationAlgorithm;
    }

    internal void UpdateOutgoingAlgorithms(Memory<byte> encryptionContext, ICryptoAlgorithm encryptionAlgorithm, Memory<byte> macGenerationContext, IMacAlgorithm macGenerationAlgorithm)
    {
        _encryptionContext.Span.Clear(); // clear the existing key material
        _encryptionContext = encryptionContext;
        _encryptionAlgorithm = encryptionAlgorithm;

        _macGenerationContext.Span.Clear(); // clear the existing key material
        _macGenerationContext = macGenerationContext;
        _macGenerationAlgorithm = macGenerationAlgorithm;
    }

    public int EncryptionAdditionalCryptoBytes => _encryptionAlgorithm.AdditionalCryptoBytes;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte EncryptionApplyPadding(Span<byte> paddingArea, int payloadLength) => _encryptionAlgorithm.ApplyPadding(paddingArea, payloadLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Encrypt(uint sequenceNumber, ReadOnlySpan<byte> binaryPacketPlaintext, Span<byte> ciphertext) => _encryptionAlgorithm.Encrypt(_encryptionContext.Span, sequenceNumber, binaryPacketPlaintext, ciphertext);



    public int DecryptionAdditionalCryptoBytes => _decryptionAlgorithm.AdditionalCryptoBytes;

    public int RequiredBytesToDecryptLength => _decryptionAlgorithm.RequiredBytesToDecryptLength;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int DecryptLength(uint sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext) => _decryptionAlgorithm.DecryptLength(_decryptionContext.Span, sequenceNumber, ciphertext, plaintext);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Decrypt(uint sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext) => _decryptionAlgorithm.Decrypt(_decryptionContext.Span, sequenceNumber, ciphertext, plaintext);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool ValidateDecryptionPayloadAndPaddingLength(int payloadLength, byte paddingAmount) => _decryptionAlgorithm.ValidatePayloadAndPaddingLength(payloadLength, paddingAmount);



    public int MacValidationLength => _macValidationAlgorithm.MacLength;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool ValidateMac(ReadOnlySpan<byte> sequenceNumberAndPacketPlaintext, ReadOnlySpan<byte> mac) => _macValidationAlgorithm.Validate(_macValidationContext.Span, sequenceNumberAndPacketPlaintext, mac);



    public int MacGenerationLength => _macGenerationAlgorithm.MacLength;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void GenerateMac(ReadOnlySpan<byte> sequenceNumberAndPacketPlaintext, Span<byte> mac) => _macGenerationAlgorithm.Generate(_macGenerationContext.Span, sequenceNumberAndPacketPlaintext, mac);
}
