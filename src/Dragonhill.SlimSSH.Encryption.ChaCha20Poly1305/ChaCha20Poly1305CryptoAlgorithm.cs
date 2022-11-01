namespace Dragonhill.SlimSSH.Algorithms;

public class ChaCha20Poly1305CryptoAlgorithm : ICryptoAlgorithm
{

    public ReadOnlySpan<byte> IdBytes => IdBytesArray;

    public int ContextSize => 0;

    public bool ReplacesMacAlgorithm => true;

    public int EffectivePaddingSize => 8;

    public int RequiredBytesToDecryptLength => 4;

    public void Encrypt(Span<byte> encryptionContext, uint sequenceNumber, ReadOnlySpan<byte> binaryPacketPlaintext, Span<byte> ciphertext)
    {
        throw new NotImplementedException();
    }

    public uint DecryptLength(Span<byte> decryptionContext, ReadOnlySpan<byte> ciphertext)
    {
        throw new NotImplementedException();
    }

    public void Decrypt(Span<byte> decryptionContext, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        throw new NotImplementedException();
    }
    
    private static readonly byte[] IdBytesArray =
        {
            (byte)'c',
            (byte)'h',
            (byte)'a',
            (byte)'c',
            (byte)'h',
            (byte)'a',
            (byte)'2',
            (byte)'0',
            (byte)'-',
            (byte)'p',
            (byte)'o',
            (byte)'l',
            (byte)'y',
            (byte)'1',
            (byte)'3',
            (byte)'0',
            (byte)'5',
            (byte)'@',
            (byte)'o',
            (byte)'p',
            (byte)'e',
            (byte)'n',
            (byte)'s',
            (byte)'s',
            (byte)'h',
            (byte)'.',
            (byte)'c',
            (byte)'o',
            (byte)'m',
        };
}
