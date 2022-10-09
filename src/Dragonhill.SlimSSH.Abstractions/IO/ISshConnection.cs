namespace Dragonhill.SlimSSH.IO;

public interface ISshConnection
{
    ISshProtocolVersion? ServerVersion { get; }

    Task Connect();
}
