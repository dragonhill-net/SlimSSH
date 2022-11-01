namespace Dragonhill.SlimSSH.Protocol;

public static class PacketConstants
{
    public const int PacketLengthOffset = 0;
    public const int PaddingOffset = PacketLengthOffset + sizeof(uint);
    public const int PayloadOffset = PaddingOffset + 1;
    public const int MessageIdOffset = PayloadOffset;
}
