namespace Dragonhill.SlimSSH.Protocol;

public static class PacketConstants
{
    public const int PacketLengthSize = sizeof(uint);
    public const int PaddingLengthSize = sizeof(byte);
    public const int MessageIdSize = sizeof(byte);

    public const int PacketLengthOffset = 0;
    public const int PaddingLengthOffset = PacketLengthOffset + PacketLengthSize;
    public const int PayloadOffset = PaddingLengthOffset + PaddingLengthSize;
    public const int MessageIdOffset = PayloadOffset;
    public const int AfterMessageIdOffset = MessageIdOffset + MessageIdSize;

    public const int PacketLengthAndPaddingLengthSize = PacketLengthSize + PaddingLengthSize;
}
