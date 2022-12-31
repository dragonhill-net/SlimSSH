using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.Protocol.Packets;

internal static class KexInit
{
    public static void Build(IAvailableSshAlgorithms availableSshAlgorithms, SshPacketPlaintextBuffer plaintextBuffer)
    {
        var payloadWriter = new SshSerializer(ref plaintextBuffer);

        payloadWriter.WriteMessageId(MessageId.KexInit);

        // Cookie
        payloadWriter.WriteCryptoRandomBytes(16);

        // KEX algorithms
        payloadWriter.WriteNameList(availableSshAlgorithms.KexAlgorithms);

        // Acceptable server host key algorithms
        payloadWriter.WriteNameList(availableSshAlgorithms.HostKeyAlgorithms);

        // Encryption algorithms
        payloadWriter.WriteNameList(availableSshAlgorithms.CryptoAlgorithms);
        payloadWriter.WriteNameList(availableSshAlgorithms.CryptoAlgorithms);

        // MAC algorithms
        payloadWriter.WriteNameList(availableSshAlgorithms.MacAlgorithms);
        payloadWriter.WriteNameList(availableSshAlgorithms.MacAlgorithms);

        // Compression algorithms, only supporting 'none'
        payloadWriter.WriteNoneNameList();
        payloadWriter.WriteNoneNameList();

        // Languages - always empty
        payloadWriter.WriteEmptyNameList();
        payloadWriter.WriteEmptyNameList();

        // First kex packet follow - never guessing - so false
        payloadWriter.WriteBoolean(false);

        // reserved
        payloadWriter.WriteUint32(0);

        payloadWriter.Finish();
    }
}
