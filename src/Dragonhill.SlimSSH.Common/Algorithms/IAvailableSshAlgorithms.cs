namespace Dragonhill.SlimSSH.Algorithms;

public interface IAvailableSshAlgorithms
{
    public IReadOnlyList<IKexAlgorithm> KexAlgorithms { get; }
    public IReadOnlyList<IHostKeyAlgorithm> HostKeyAlgorithms { get; }
    public IReadOnlyList<ICryptoAlgorithm> CryptoAlgorithms { get; }
    public IReadOnlyList<IMacAlgorithm> MacAlgorithms { get; }
}
