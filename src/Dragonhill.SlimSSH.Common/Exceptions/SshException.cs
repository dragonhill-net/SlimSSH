using Dragonhill.SlimSSH.Protocol;

namespace Dragonhill.SlimSSH.Exceptions;

public class SshException : Exception
{
    public DisconnectReasonCode? DisconnectReason { get; }

    public SshException(string message, Exception? innerException = null)
        : base(message, innerException)
    {

    }

    public SshException(DisconnectReasonCode disconnectReason, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        DisconnectReason = disconnectReason;
    }
}
