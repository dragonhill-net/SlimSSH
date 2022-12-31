namespace Dragonhill.SlimSSH.Algorithms;

public class StandardAlgorithmSet : IAvailableSshAlgorithms
{
    public static readonly StandardAlgorithmSet Instance = new();

    private readonly IKexAlgorithm[] _standardKexAlgorithms = { new Curve25519Sha256LibsshOrgKexAlgorithm() };
    private readonly IHostKeyAlgorithm[] _standardServerHostKeyAlgorithms = { new Ed25519HostKeyAlgorithm(), new RsaSha512HostKeyAlgorithm(), new RsaSha256HostKeyAlgorithm() };
    private readonly ICryptoAlgorithm[] _standardEncryptionAlgorithms = { new ChaCha20Poly1305CryptoAlgorithm() };
    private readonly IMacAlgorithm[] _standardMacAlgorithms = Array.Empty<IMacAlgorithm>();

    public IReadOnlyList<IKexAlgorithm> KexAlgorithms => _standardKexAlgorithms;
    public IReadOnlyList<IHostKeyAlgorithm> HostKeyAlgorithms => _standardServerHostKeyAlgorithms;
    public IReadOnlyList<ICryptoAlgorithm> CryptoAlgorithms => _standardEncryptionAlgorithms;
    public IReadOnlyList<IMacAlgorithm> MacAlgorithms => _standardMacAlgorithms;
}
