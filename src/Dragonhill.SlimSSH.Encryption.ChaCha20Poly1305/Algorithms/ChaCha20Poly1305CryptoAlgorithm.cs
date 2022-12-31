using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Interop;
using Dragonhill.SlimSSH.Protocol;

namespace Dragonhill.SlimSSH.Algorithms;

public class ChaCha20Poly1305CryptoAlgorithm : ICryptoAlgorithm
{
    private const int EffectivePaddingBlockSize = 8;

    public ReadOnlySpan<byte> IdBytes => IdBytesArray;

    public bool ReplacesMacAlgorithm => true;

    public int AdditionalCryptoBytes => LibSodium.Poly1305TagLength;

    public int RequiredContextSize => RequiredKeyBytes;

    public int RequiredInitializationVectorBytes => 0;

    public int RequiredKeyBytes => LibSodium.ChaCha20KeyLength * 2;

    public void Init(Span<byte> encryptionContext, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> key)
    {
        key.CopyTo(encryptionContext);
    }

    public byte ApplyPadding(Span<byte> paddingArea, int payloadLength)
    {
        // the length field is not included in the padding calculation as it is encrypted separately
        return PaddingHelper.CalculateAndRandomFillPadding(paddingArea, PacketConstants.PaddingLengthSize + payloadLength, EffectivePaddingBlockSize);
    }

    public int RequiredBytesToDecryptLength => sizeof(uint);

    public unsafe void Encrypt(Span<byte> encryptionContext, uint sequenceNumber, ReadOnlySpan<byte> binaryPacketPlaintext, Span<byte> ciphertext)
    {
        if (ciphertext.Length != binaryPacketPlaintext.Length + AdditionalCryptoBytes)
        {
            SshExceptionThrowHelper.ArgumentOutOfRange(nameof(ciphertext));
        }

        Span<byte> nonce = stackalloc byte[LibSodium.NonceLength];
        SshPrimitives.WriteUint64(nonce, sequenceNumber);

        fixed (byte* encryptionContextPtr = encryptionContext)
        fixed (byte* binaryPacketPlaintextPtr = binaryPacketPlaintext)
        fixed (byte* ciphertextPtr = ciphertext)
        fixed (byte* noncePtr = nonce)
        {
            var k2 = encryptionContextPtr;
            var k1 = encryptionContextPtr + LibSodium.ChaCha20KeyLength;

            // encrypt the packet length
            if(LibSodium.crypto_stream_chacha20_xor(ciphertextPtr, binaryPacketPlaintextPtr, PacketConstants.PacketLengthSize, noncePtr, k1) != 0)
            {
                SshExceptionThrowHelper.InteropError();
            }

            // generate the poly1305 key
            var poly1305Key = stackalloc byte[LibSodium.Poly1305KeyLength];
            if (LibSodium.crypto_stream_chacha20(poly1305Key, LibSodium.Poly1305KeyLength, noncePtr, k2) != 0)
            {
                SshExceptionThrowHelper.InteropError();
            }

            // encrypt the remaining data
            if(LibSodium.crypto_stream_chacha20_xor_ic(ciphertextPtr + PacketConstants.PacketLengthSize, binaryPacketPlaintextPtr + PacketConstants.PacketLengthSize, (ulong)binaryPacketPlaintext.Length - PacketConstants.PacketLengthSize, noncePtr, 1, k2) != 0)
            {
                SshExceptionThrowHelper.InteropError();
            }

            // create the poly 1305 tag
            if(LibSodium.crypto_onetimeauth_poly1305(ciphertextPtr + binaryPacketPlaintext.Length, ciphertextPtr, (ulong)binaryPacketPlaintext.Length, poly1305Key) != 0)
            {
                SshExceptionThrowHelper.InteropError();
            }
        }
    }

    public unsafe int DecryptLength(Span<byte> decryptionContext, uint sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        if (ciphertext.Length < RequiredBytesToDecryptLength)
        {
            SshExceptionThrowHelper.ArgumentOutOfRange(nameof(ciphertext));
        }

        if (plaintext.Length < RequiredBytesToDecryptLength)
        {
            SshExceptionThrowHelper.ArgumentOutOfRange(nameof(plaintext));
        }

        Span<byte> nonce = stackalloc byte[LibSodium.NonceLength];
        SshPrimitives.WriteUint64(nonce, sequenceNumber);

        fixed (byte* decryptionContextPtr = decryptionContext)
        fixed (byte* plaintextPtr = plaintext)
        fixed (byte* ciphertextPtr = ciphertext)
        fixed (byte* noncePtr = nonce)
        {
            var k1 = decryptionContextPtr + LibSodium.ChaCha20KeyLength;

            // decrypt the packet length
            if(LibSodium.crypto_stream_chacha20_xor(plaintextPtr, ciphertextPtr, PacketConstants.PacketLengthSize, noncePtr, k1) != 0)
            {
                SshExceptionThrowHelper.InteropError();
            }
        }

        return PacketConstants.PacketLengthSize;
    }

    public unsafe void Decrypt(Span<byte> decryptionContext, uint sequenceNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        // the packet length must already be present at the beginning of the plaintext buffer
        var packetLength = SshPrimitives.ReadUint32(plaintext);
        var tagOffset = PacketConstants.PacketLengthSize + packetLength;

        if (plaintext.Length < tagOffset)
        {
            SshExceptionThrowHelper.ArgumentOutOfRange(nameof(plaintext));
        }

        if (ciphertext.Length < tagOffset + LibSodium.Poly1305TagLength)
        {
            SshExceptionThrowHelper.ArgumentOutOfRange(nameof(ciphertext));
        }

        Span<byte> nonce = stackalloc byte[LibSodium.NonceLength];
        SshPrimitives.WriteUint64(nonce, sequenceNumber);

        fixed (byte* decryptionContextPtr = decryptionContext)
        fixed (byte* plaintextPtr = plaintext)
        fixed (byte* ciphertextPtr = ciphertext)
        fixed (byte* noncePtr = nonce)
        {
            var k2 = decryptionContextPtr;

            // generate the poly1305 key
            var poly1305Key = stackalloc byte[LibSodium.Poly1305KeyLength];
            if (LibSodium.crypto_stream_chacha20(poly1305Key, LibSodium.Poly1305KeyLength, noncePtr, k2) != 0)
            {
                SshExceptionThrowHelper.InteropError();
            }

            // validate the poly1305 tag
            switch (LibSodium.crypto_onetimeauth_poly1305_verify(ciphertextPtr + tagOffset, ciphertextPtr, packetLength + PacketConstants.PacketLengthSize, poly1305Key))
            {
                case 0:
                    break;

                case -1:
                    SshExceptionThrowHelper.MacVerificationError();
                    break;

                default:
                    SshExceptionThrowHelper.InteropError();
                    break;
            }

            // decrypt the data
            if(LibSodium.crypto_stream_chacha20_xor_ic(plaintextPtr + PacketConstants.PacketLengthSize, ciphertextPtr + PacketConstants.PacketLengthSize, packetLength, noncePtr, 1, k2) != 0)
            {
                SshExceptionThrowHelper.InteropError();
            }
        }
    }

    public bool ValidatePayloadAndPaddingLength(int payloadLength, byte paddingAmount)
    {
        // the length field is not included in the padding calculation as it is encrypted separately
        return PaddingHelper.CalculatePaddingLength(PacketConstants.PaddingLengthSize + payloadLength, EffectivePaddingBlockSize) == paddingAmount;
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
