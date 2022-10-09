using System;
using System.Collections.Concurrent;
using System.IO;

namespace Dragonhill.SlimSSH.TestHelpers;

internal class MockChunkedStream : Stream
{
    private readonly BlockingCollection<byte[]> _readDataChunks = new();
    private byte[]? _remainingChunk = null;

    internal void AddReadDataChunk(byte[]chunk)
    {
        _readDataChunks.Add(chunk);
    }

    public override void Flush() {}

    public override int Read(byte[] buffer, int offset, int count)
    {
        var chunk = _remainingChunk ?? _readDataChunks.Take();
        _remainingChunk = null;

        if (chunk.Length == 0)
        {
            return 0;
        }

        if (chunk.Length <= count)
        {
            chunk.AsSpan().CopyTo(buffer.AsSpan(offset..));
            return chunk.Length;
        }

        chunk.AsSpan(..count).CopyTo(buffer.AsSpan(offset..));
        _remainingChunk = chunk[count..];

        return count;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotImplementedException();
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }
}
