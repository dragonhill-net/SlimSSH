namespace Dragonhill.SlimSSH.Algorithms;

public interface IMacAlgorithm : IAlgorithmId
{
    int RequiredContextSize { get; }

    public int RequiredKeySize { get; }

    void Init(Span<byte> encryptionContext, ReadOnlySpan<byte> key);

    public int MacLength { get; }

    public void Generate(Span<byte> macGenerationContext, ReadOnlySpan<byte> sequenceNumberAndPacketPlaintext, Span<byte> mac);

    public bool Validate(Span<byte> macVerifyContext, ReadOnlySpan<byte> sequenceNumberAndPacketPlaintextIncluding, ReadOnlySpan<byte> mac);
}
