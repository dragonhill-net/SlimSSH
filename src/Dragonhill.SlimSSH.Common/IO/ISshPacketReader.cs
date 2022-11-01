using Dragonhill.SlimSSH.Data;
using Dragonhill.SlimSSH.Helpers;

namespace Dragonhill.SlimSSH.IO;

internal interface ISshPacketReader : IAsyncDisposable
{
    SshProtocolVersion? PeerVersion { get; }
    Task Run(CancellationToken cancellationToken);

    /// <remarks>
    /// Note: The caller is responsible for calling <see cref="PooledBufferWrapper.Dispose"/> if the return value is not null.
    /// </remarks>
    ValueTask<PooledBufferWrapper?> ReadPacket();
}
