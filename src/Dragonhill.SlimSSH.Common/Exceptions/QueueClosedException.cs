namespace Dragonhill.SlimSSH.Exceptions;

public class QueueClosedException : Exception
{
    public static void ThrowHelper()
    {
        throw new QueueClosedException();
    }
}
