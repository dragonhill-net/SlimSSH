using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.IO;

internal interface ISshPacketWriter
{
    int RequiredBytesInFrontOfBuffer { get; }
    int MaxPaddingSize { get; }

    /// <remarks>The first <see cref="SshPacketWriter.RequiredBytesInFrontOfBuffer"/> bytes of the memory must not be used as they will be overwritten</remarks>
    ValueTask WritePacket(SshUnfinishedPacket unfinishedPacket);

    Task Run(CancellationToken cancellationToken);
}
