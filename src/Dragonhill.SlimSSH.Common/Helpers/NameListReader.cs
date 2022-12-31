using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Localization;
using System.Text;

namespace Dragonhill.SlimSSH.Helpers;

public readonly ref struct NameListReader
{
    public ref struct Iterator
    {
        private ReadOnlySpan<byte> _contentBuffer;

        internal Iterator(ReadOnlySpan<byte> contentBuffer)
        {
            _contentBuffer = contentBuffer;
        }

        public ReadOnlySpan<byte> NextString()
        {
            var separatorPos = _contentBuffer.IndexOf((byte)',');

            ReadOnlySpan<byte> retval;

            if (separatorPos < 0)
            {
                retval = _contentBuffer;
                _contentBuffer = ReadOnlySpan<byte>.Empty;
            }
            else
            {
                retval = _contentBuffer[..separatorPos];
                _contentBuffer = _contentBuffer[(separatorPos + 1)..];
            }

            return retval;
        }
    }

    private readonly ReadOnlySpan<byte> _content;
    //private readonly int _maxStringLength;

    public NameListReader(ReadOnlySpan<byte> content)
    {
        _content = content;

        if (content.IsEmpty)
        {
            return;
        }

        var currentStringLength = 0;
        foreach (var contentByte in _content)
        {
            switch (contentByte)
            {
                case (byte)',' when currentStringLength == 0:
                    throw new SshException(Strings.NameList_EmptyString);

                case (byte)',':
                    currentStringLength = 0;
                    break;

                case <= 0x1F or >= 0x7F:
                    throw new SshException(Strings.NameList_InvalidCharacter);
            }

            ++currentStringLength;
        }

        if (currentStringLength == 0)
        {
            throw new SshException(Strings.NameList_EmptyString);
        }
    }

    public Iterator GetIterator()
    {
        return new Iterator(_content);
    }

    public IReadOnlyList<string> ToStrings()
    {
        List<string> list = new();

        var iterator = GetIterator();
        ReadOnlySpan<byte> next;
        while (!(next = iterator.NextString()).IsEmpty)
        {
            list.Add(Encoding.ASCII.GetString(next));
        }

        return list;
    }
}
