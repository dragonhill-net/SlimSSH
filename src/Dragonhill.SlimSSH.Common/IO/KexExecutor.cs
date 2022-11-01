using Dragonhill.SlimSSH.Algorithms;
using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;

namespace Dragonhill.SlimSSH.IO;

internal static class KexExecutor
{
    private static (IKexAlgorithm, IHostKeyAlgorithm, bool) FindKeyAndHostKeyAlgorithm(IAvailableSshAlgorithms availableSshAlgorithms, ref SshPacketDeserializer deserializer)
    {
        var correctGuess = true;

        var serverKexAlgorithms = deserializer.ReadNameList();
        var serverHostKeyAlgorithms = deserializer.ReadNameList();

        foreach (var clientKexAlgorithm in availableSshAlgorithms.KexAlgorithms)
        {
            var serverKexAlgorithmIterator = serverKexAlgorithms.GetIterator();
            ReadOnlySpan<byte> serverKexAlgorithm;
            while (!(serverKexAlgorithm = serverKexAlgorithmIterator.NextString()).IsEmpty)
            {
                if (!serverKexAlgorithm.SequenceEqual(clientKexAlgorithm.IdBytes)) // find the first client kex algorithm the server supports
                {
                    correctGuess = false;
                    continue;
                }

                foreach (var clientServerHostKeyAlgorithm in availableSshAlgorithms.HostKeyAlgorithms)
                {
                    var serverServerHostKeyAlgorithmIterator = serverHostKeyAlgorithms.GetIterator();
                    ReadOnlySpan<byte> serverServerHostKeyAlgorithm;
                    while (!(serverServerHostKeyAlgorithm = serverServerHostKeyAlgorithmIterator.NextString()).IsEmpty)
                    {
                        if (!serverServerHostKeyAlgorithm.SequenceEqual(clientServerHostKeyAlgorithm.IdBytes)) // find the first client server host key algorithm the server supports
                        {
                            continue;
                        }

                        if (clientKexAlgorithm.RequiresSignatureCapableHostKey && !clientServerHostKeyAlgorithm.SupportsSignature)
                        {
                            continue;
                        }

                        if (clientKexAlgorithm.RequiresEncryptionCapableHostKey && !clientServerHostKeyAlgorithm.SupportsEncryption)
                        {
                            continue;
                        }

                        return (clientKexAlgorithm, clientServerHostKeyAlgorithm, correctGuess);
                    }
                }

                correctGuess = false;
            }

            correctGuess = false;
        }

        throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_NoKexAlgorithmMatch);
    }

    private static TAlgorithm FindAlgorithm<TAlgorithm>(IReadOnlyList<TAlgorithm> clientAlgorithms, ref SshPacketDeserializer deserializer, Func<string> errorMessage)
        where TAlgorithm: IAlgorithmId
    {
        var serverAlgorithms = deserializer.ReadNameList();

        foreach (var clientAlgorithm in clientAlgorithms)
        {
            var serverAlgorithmsIterator = serverAlgorithms.GetIterator();
            ReadOnlySpan<byte> serverAlgorithm;
            while (!(serverAlgorithm = serverAlgorithmsIterator.NextString()).IsEmpty)
            {
                if (serverAlgorithm.SequenceEqual(clientAlgorithm.IdBytes))
                {
                    return clientAlgorithm;
                }
            }
        }

        throw new SshException(DisconnectReasonCode.KeyExchangeFailed, errorMessage());
    }

    private static IMacAlgorithm FindMacAlgorithm(IReadOnlyList<IMacAlgorithm> clientAlgorithms, ICryptoAlgorithm cryptoAlgorithm, ref SshPacketDeserializer deserializer, Func<string> errorMessage)
    {
        if (!cryptoAlgorithm.ReplacesMacAlgorithm)
        {
            return FindAlgorithm(clientAlgorithms, ref deserializer, errorMessage);
        }

        deserializer.ReadNameList();
        return NoneMacAlgorithm.Instance;
    }

    private static void EnsureNoneIsSupported(ref SshPacketDeserializer deserializer, Func<string> errorMessage)
    {
        var serverNameList = deserializer.ReadNameList();

        var serverNameListIterator = serverNameList.GetIterator();
        ReadOnlySpan<byte> serverName;
        while (!(serverName = serverNameListIterator.NextString()).IsEmpty)
        {
            if (serverName.SequenceEqual(Constants.NoneBytes.Span))
            {
                return;
            }
        }

        throw new SshException(DisconnectReasonCode.KeyExchangeFailed, errorMessage());
    }

    internal static ValueTask StartKex(AlgorithmContext algorithmContext, KexContext context, ISafePacketSender safePacketSender)
    {
        var availableSshAlgorithms = algorithmContext.AvailableSshAlgorithms;

        var deserializer = new SshPacketDeserializer(context.GetPeerKexInitPacketPayload());

        deserializer.ReadByte(); // message id

        deserializer.ReadBytes(16); // cookie

        var (kexAlgorithm, hostKeyAlgorithm, correctGuess) = FindKeyAndHostKeyAlgorithm(availableSshAlgorithms, ref deserializer);

        var encryptionAlgorithmClientToServer = FindAlgorithm(availableSshAlgorithms.CryptoAlgorithms, ref deserializer, () => Strings.Transport_NoKexCryptoMatch);
        var encryptionAlgorithmServerToClient = FindAlgorithm(availableSshAlgorithms.CryptoAlgorithms, ref deserializer, () => Strings.Transport_NoKexCryptoMatch);

        var macAlgorithmsClientToServer = FindMacAlgorithm(availableSshAlgorithms.MacAlgorithms, encryptionAlgorithmClientToServer, ref deserializer, () => Strings.Transport_NoKexMacMatch);
        var macAlgorithmsServerToClient = FindMacAlgorithm(availableSshAlgorithms.MacAlgorithms, encryptionAlgorithmServerToClient, ref deserializer, () => Strings.Transport_NoKexMacMatch);

        EnsureNoneIsSupported(ref deserializer, () => Strings.Transport_NoKexUncompressedSupported); // compression client to server
        EnsureNoneIsSupported(ref deserializer, () => Strings.Transport_NoKexUncompressedSupported); // compression server to client

        // language name list is ignored
        deserializer.ReadNameList();
        deserializer.ReadNameList();

        var firstKexPacketFollows = deserializer.ReadBoolean();

        var reserved = deserializer.ReadUint32();

        if (reserved != 0)
        {
            throw new SshException(DisconnectReasonCode.KeyExchangeFailed, Strings.Transport_ReservedNotZero);
        }

        deserializer.CheckReadEverything();

        context.SetAlgorithms(kexAlgorithm, hostKeyAlgorithm, encryptionAlgorithmClientToServer, encryptionAlgorithmServerToClient, macAlgorithmsClientToServer, macAlgorithmsServerToClient);

        if (firstKexPacketFollows && !correctGuess)
        {
            context.SetIgnoreNextKexPacket();
        }

        return kexAlgorithm.StartKex(context, safePacketSender);
    }

    internal static async ValueTask<SshPacketBuilder> SendKexInit(IAvailableSshAlgorithms availableSshAlgorithms, ISshPacketWriter writer)
    {
        var packetBuilder = new SshPacketBuilder(writer);

        try
        {
            packetBuilder.WriteMessageId(MessageId.KexInit);

            // Cookie
            packetBuilder.WriteCryptoRandomBytes(16);

            // KEX algorithms
            packetBuilder.WriteNameList(availableSshAlgorithms.KexAlgorithms);

            // Acceptable server host key algorithms
            packetBuilder.WriteNameList(availableSshAlgorithms.HostKeyAlgorithms);

            // Encryption algorithms
            packetBuilder.WriteNameList(availableSshAlgorithms.CryptoAlgorithms);
            packetBuilder.WriteNameList(availableSshAlgorithms.CryptoAlgorithms);

            // MAC algorithms
            packetBuilder.WriteNameList(availableSshAlgorithms.MacAlgorithms);
            packetBuilder.WriteNameList(availableSshAlgorithms.MacAlgorithms);

            // Compression algorithms, only supporting 'none'
            packetBuilder.WriteNoneNameList();
            packetBuilder.WriteNoneNameList();

            // Languages - always empty
            packetBuilder.WriteEmptyNameList();
            packetBuilder.WriteEmptyNameList();

            // First kex packet follow - never guessing - so false
            packetBuilder.WriteBoolean(false);

            // reserved
            packetBuilder.WriteUint32(0);

            await writer.WritePacket(packetBuilder.GetUnfinishedPacket());

            return packetBuilder;
        }
        catch
        {
            packetBuilder.Dispose();
            throw;
        }
    }
}
