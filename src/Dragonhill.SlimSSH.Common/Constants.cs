namespace Dragonhill.SlimSSH;

public static class Constants
{
    public const string VersionName = "DragonhillSlimSSH";

    public const uint ProtocolVersionExchangeMaxLineLength = 255;

    public const uint MaxAllowedPacketSize = 256 * 1024;

    public const int RequiredSupportedPayloadSize = 32768;

    public const int KexAfterBytes = 1024 * 1024 * 1024;
    public const int KexAfterMilliseconds = 60 * 60 * 1000;

    public static readonly ReadOnlyMemory<byte> NoneBytes = new byte[]
        {
            (byte)'n',
            (byte)'o',
            (byte)'n',
            (byte)'e'
        };
}
