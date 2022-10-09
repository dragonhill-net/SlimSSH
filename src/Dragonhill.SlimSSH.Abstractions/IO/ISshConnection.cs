namespace Dragonhill.SlimSSH.IO;

public interface ISshConnection
{
    bool IsClosed { get; }

    ISshProtocolVersion? ServerVersion { get; }

    Task Connect(TimeSpan? timeout = null);

    Task WaitClose(TimeSpan? timeout = null, CancellationToken cancellationToken = default);
}
