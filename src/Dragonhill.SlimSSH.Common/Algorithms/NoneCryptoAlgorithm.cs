using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.Algorithms;

public class NoneCryptoAlgorithm : ICryptoAlgorithm
{
    public static readonly ICryptoAlgorithm Instance = new NoneCryptoAlgorithm();

    public int ContextSize => 0;
    public ReadOnlySpan<byte> IdBytes => Constants.NoneBytes.Span;

    public bool ReplacesMacAlgorithm => false;

    public int EffectivePaddingSize => 8;

    public void Encrypt(Span<byte> encryptionContext, uint sequenceNumber, ReadOnlySpan<byte> binaryPacketPlaintext, Span<byte> ciphertext)
    {
        binaryPacketPlaintext.CopyTo(ciphertext);
    }


    public int RequiredBytesToDecryptLength => sizeof(uint);

    public uint DecryptLength(Span<byte> decryptionContext, ReadOnlySpan<byte> ciphertext)
    {
        return SshPrimitives.ReadUint32(ciphertext);
    }

    public void Decrypt(Span<byte> decryptionContext, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        ciphertext.CopyTo(plaintext);
    }
}
