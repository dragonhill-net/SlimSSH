using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.Protocol.Packets;

public static class Disconnect
{
    public static void Build(SshPacketPlaintextBuffer plaintextBuffer, DisconnectReasonCode disconnectReasonCode, string? description)
    {
        var payloadWriter = new SshSerializer(ref plaintextBuffer);

        payloadWriter.WriteMessageId(MessageId.Disconnect);
        payloadWriter.WriteUint32((uint)disconnectReasonCode);
        payloadWriter.WriteString(description ?? string.Empty);
        payloadWriter.WriteBytesString(ReadOnlySpan<byte>.Empty);

        payloadWriter.Finish();
    }
}
