using Dragonhill.SlimSSH;

//var client = SshClientFactory.CreateNewTcp("127.0.0.1", 2222);
var client = SshClientFactory.CreateNewTcp("127.0.0.1", 10022);

try
{
    await client.Connect();

    await client.TryReadPacket();
}
catch (Exception exception)
{
    Console.WriteLine(exception.Message);
}
