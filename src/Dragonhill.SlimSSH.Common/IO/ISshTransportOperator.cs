namespace Dragonhill.SlimSSH.IO;

public interface ISshTransportOperator
{
    ValueTask RequestKeyExchange();
}
