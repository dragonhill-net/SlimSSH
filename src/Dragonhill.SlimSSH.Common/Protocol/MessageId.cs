namespace Dragonhill.SlimSSH.Protocol;

public enum MessageId : byte
{
    Disconnect = 1,
    KexInit = 20,
    NewKeys = 21
}
