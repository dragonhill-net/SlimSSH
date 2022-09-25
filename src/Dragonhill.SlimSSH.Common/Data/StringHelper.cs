using System.Text;

namespace Dragonhill.SlimSSH.Data;

public static class StringHelper
{
    public static bool TryParseProtocolVersionExchangeString(ReadOnlySpan<byte> input, out string str)
    {
        str = Encoding.ASCII.GetString(input);

        return !str.Any(c => c == '-' || !char.IsAscii(c) || char.IsWhiteSpace(c) || char.IsControl(c));
    }
}
