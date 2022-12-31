using Dragonhill.SlimSSH.Exceptions;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Dragonhill.SlimSSH.Interop;

internal static partial class LibSodium
{
    static LibSodium()
    {
        if (sodium_init() < 0)
        {
            SshExceptionThrowHelper.InteropError();
        }
    }

    private const string LibraryName = "libsodium";
    internal const int ChaCha20KeyLength = 32;
    internal const int Poly1305KeyLength = 32;
    internal const int Poly1305TagLength = 16;
    internal const int NonceLength = 8;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [LibraryImport(LibraryName)]
    [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
    internal static partial int sodium_init();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [LibraryImport(LibraryName)]
    [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
    internal static unsafe partial int crypto_stream_chacha20(byte* c, ulong clen, byte* n, byte* k);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [LibraryImport(LibraryName)]
    [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
    internal static unsafe partial int crypto_stream_chacha20_xor(byte* c, byte* m, ulong mlen, byte* n, byte* k);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [LibraryImport(LibraryName)]
    [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
    internal static unsafe partial int crypto_stream_chacha20_xor_ic(byte* c, byte* m, ulong mlen, byte* n, ulong ic, byte* k);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [LibraryImport(LibraryName)]
    [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
    internal static unsafe partial int crypto_onetimeauth_poly1305(byte* @out, byte* @in, ulong inlen, byte* k);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [LibraryImport(LibraryName)]
    [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
    internal static unsafe partial int crypto_onetimeauth_poly1305_verify(byte* h, byte* @in, ulong inlen, byte* k);
}
