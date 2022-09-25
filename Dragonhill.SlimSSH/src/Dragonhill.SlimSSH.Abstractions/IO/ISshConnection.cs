namespace Dragonhill.SlimSSH.IO;

public interface ISshConnection
{
    string? ServerSoftwareVersion { get; }
    string? ServerComment { get; }

    Task Connect();
}
