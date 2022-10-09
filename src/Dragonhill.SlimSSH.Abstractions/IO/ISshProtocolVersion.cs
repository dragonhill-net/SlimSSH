namespace Dragonhill.SlimSSH.IO;

public interface ISshProtocolVersion
{
    public string SoftwareVersion { get; }
    public string? Comment { get; }
}
