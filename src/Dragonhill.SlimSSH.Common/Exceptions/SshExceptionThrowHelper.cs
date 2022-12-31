using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Protocol;

namespace Dragonhill.SlimSSH.Exceptions;

public static class SshExceptionThrowHelper
{
    public static void NoMessageId()
    {
        throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Packet_NoMessageId);
    }

    public static void UnexpectedPacket()
    {
        throw new SshException(DisconnectReasonCode.ProtocolError, Strings.Transport_UnexpectedPacket);
    }

    public static void PayloadOutOfRange()
    {
        throw new SshException(Strings.Packet_PayloadOutOfRange);
    }

    public static void PeerUnimplemented()
    {
        throw new SshException(Strings.Transport_PeerSendUnimplemented);
    }

    public static void ConnectNotStarted()
    {
        throw new SshException(Strings.SshConnectionBase_NotStarted);
    }

    public static void ReferenceCountZero()
    {
        throw new ObjectDisposedException(Strings.ReferenceCountZero, (Exception?)null);
    }

    public static void InteropError()
    {
        throw new SshException(Strings.Interop_NativeLibraryError);
    }

    public static void ArgumentOutOfRange(string paramName)
    {
        throw new ArgumentOutOfRangeException(paramName);
    }

    public static void MacVerificationError()
    {
        throw new SshException(DisconnectReasonCode.MacError, Strings.Packet_MacError);
    }
}
