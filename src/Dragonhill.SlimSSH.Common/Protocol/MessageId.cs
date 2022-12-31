namespace Dragonhill.SlimSSH.Protocol;

public enum MessageId : byte
{
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    KexInit = 20,
    NewKeys = 21
}
