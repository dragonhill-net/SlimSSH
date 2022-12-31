using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.Protocol.Packets;

public class Debug
{
    public static void Build(SshPacketPlaintextBuffer plaintextBuffer, bool alwaysDisplay, string message)
    {
        var payloadWriter = new SshSerializer(ref plaintextBuffer);

        payloadWriter.WriteMessageId(MessageId.Debug);
        payloadWriter.WriteBoolean(alwaysDisplay);
        payloadWriter.WriteString(message);
        payloadWriter.WriteString(string.Empty);

        payloadWriter.Finish();
    }
}
