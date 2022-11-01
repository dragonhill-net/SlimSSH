namespace Dragonhill.SlimSSH.Algorithms;

public class NoneMacAlgorithm : IMacAlgorithm
{
    public static readonly NoneMacAlgorithm Instance = new();

    public ReadOnlySpan<byte> IdBytes => Constants.NoneBytes.Span;

    public int MacLength => 0;

    public int ContextSize => 0;

    public void Generate(Span<byte> macGenerationContext, ReadOnlySpan<byte> sequenceNumberAndPacketPlaintext, Span<byte> mac)
    {
    }

    public bool Validate(Span<byte> macVerifyContext, ReadOnlySpan<byte> sequenceNumberAndPacketPlaintextIncluding, ReadOnlySpan<byte> mac)
    {
        return true;
    }
}
