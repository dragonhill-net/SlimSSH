namespace Dragonhill.SlimSSH.Algorithms;

public readonly struct AvailableAlgorithmsMetrics
{
    public int TotalContextSize { get; } = 0;
    public int MaxCryptoContextSize { get; } = 0;
    public int MaxMacContextSize { get; } = 0;

    public int EncryptionContextOffset => 0;
    public int DecryptionContextOffset { get; }
    public int MacGenerationContextOffset { get; }
    public int MacValidationContextOffset { get; }

    public int MaxPaddingSize { get; }

    public AvailableAlgorithmsMetrics(IAvailableSshAlgorithms availableSshAlgorithms)
    {
        MaxCryptoContextSize = availableSshAlgorithms.CryptoAlgorithms.Max(x => x.ContextSize);
        MaxMacContextSize = availableSshAlgorithms.MacAlgorithms.Count > 0 ? availableSshAlgorithms.MacAlgorithms.Max(x => x.ContextSize) : 0;

        TotalContextSize = 2 * (MaxCryptoContextSize + MaxMacContextSize);

        DecryptionContextOffset = MaxCryptoContextSize;
        MacGenerationContextOffset = 2 * MaxCryptoContextSize;
        MacValidationContextOffset = MacGenerationContextOffset + MaxMacContextSize;

        MaxPaddingSize = availableSshAlgorithms.CryptoAlgorithms.Max(x => x.EffectivePaddingSize) + 3; // at least 4 bytes of padding
    }
}
