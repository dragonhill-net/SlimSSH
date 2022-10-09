namespace Dragonhill.SlimSSH.Exceptions;

public class SshException : Exception
{
    public SshException(string message, Exception? innerException = null)
        : base(message, innerException)
    {

    }
}
