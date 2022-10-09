using System.Text;

namespace Dragonhill.SlimSSH.Data;

public static class StringHelper
{
    public static bool TryParseProtocolVersionExchangeString(ReadOnlySpan<byte> input, out string str)
    {
        // Using UTF8 instead of ASCII as the error replacement char of ASCII is '?' which would be valid
        str = Encoding.UTF8.GetString(input);

        if (str.Any(c => c == '-' || !char.IsAscii(c) || char.IsWhiteSpace(c) || char.IsControl(c)))
        {
            str = string.Empty;
            return false;
        }

        return true;
    }
}
