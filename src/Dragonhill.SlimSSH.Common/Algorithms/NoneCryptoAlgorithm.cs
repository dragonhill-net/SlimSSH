using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Protocol;

namespace Dragonhill.SlimSSH.Algorithms;

public class NoneCryptoAlgorithm : ICryptoAlgorithm
{
    private const int EffectivePaddingBlockSize = 8;

    public static readonly ICryptoAlgorithm Instance = new NoneCryptoAlgorithm();

    public ReadOnlySpan<byte> IdBytes => Constants.NoneBytes.Span;

    public bool ReplacesMacAlgorithm => false;

    public int AdditionalCryptoBytes => 0;

    public int RequiredContextSize => 0;

    public int RequiredInitializationVectorBytes => 0;

    public int RequiredKeyBytes => 0;

    public void Init(Span<byte> encryptionContext, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> key) {}
    public byte ApplyPadding(Span<byte> paddingArea, int payloadLength)
    {
        return PaddingHelper.CalculateAndRandomFillPadding(paddingArea, PacketConstants.PacketLengthAndPaddingLengthSize + payloadLength, EffectivePaddingBlockSize);
    }

    public void Encrypt(Span<byte> encryptionContext, uint sequenceNumber, ReadOnlySpan<byte> binaryPacketPlaintext, Span<byte> ciphertext)
    {
        binaryPacketPlaintext.CopyTo(ciphertext);
    }

    public int RequiredBytesToDecryptLength => sizeof(uint);

    public int DecryptLength(Span<byte> decryptionContext, uint sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        ciphertext[..PacketConstants.PacketLengthSize].CopyTo(plaintext);
        return PacketConstants.PacketLengthSize;
    }

    public void Decrypt(Span<byte> decryptionContext, uint sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        ciphertext[PacketConstants.PacketLengthSize..].CopyTo(plaintext[PacketConstants.PacketLengthSize..]);
    }

    public bool ValidatePayloadAndPaddingLength(int payloadLength, byte paddingAmount)
    {
        return PaddingHelper.CalculatePaddingLength(PacketConstants.PacketLengthAndPaddingLengthSize + payloadLength, EffectivePaddingBlockSize) == paddingAmount;
    }
}
