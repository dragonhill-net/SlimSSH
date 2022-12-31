using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.Protocol.Packets;

internal static class NewKeys
{
    public static void Build(SshPacketPlaintextBuffer plaintextBuffer)
    {
        var payloadWriter = new SshSerializer(ref plaintextBuffer);

        payloadWriter.WriteMessageId(MessageId.NewKeys);

        payloadWriter.Finish();
    }
}
