using System.Text;

namespace Dragonhill.SlimSSH.Algorithms;

public interface IAlgorithmId
{
    ReadOnlySpan<byte> IdBytes { get; }

    string IdString => Encoding.UTF8.GetString(IdBytes);
}
