using Dragonhill.SlimSSH.Protocol;
using System.Buffers;

namespace Dragonhill.SlimSSH.Helpers;

internal readonly struct PooledBufferWrapper : IDisposable
{
    private readonly byte[] _buffer;
    private readonly int _start;
    private readonly int _length;

    public PooledBufferWrapper(byte[] buffer, int start, int length)
    {
        _buffer = buffer;
        _start = start;
        _length = length;
    }

    public ReadOnlySpan<byte> AsSpan()
    {
        return _buffer.AsSpan(_start, _length);
    }

    private Range PayloadRange()
    {
        var paddingBytes = _buffer[_start + PacketConstants.PaddingOffset];
        return new Range(_start + PacketConstants.PayloadOffset, _start + _length - paddingBytes);
    }

    public ReadOnlySpan<byte> GetPayloadSpan()
    {
        return _buffer.AsSpan(PayloadRange());
    }

    public ReadOnlyMemory<byte> GetPayloadMemory()
    {
        return _buffer.AsMemory(PayloadRange());
    }

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(_buffer);
    }
}
