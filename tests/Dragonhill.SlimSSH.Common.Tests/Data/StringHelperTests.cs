using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Dragonhill.SlimSSH.Data;

public class StringHelperTests
{
    [Fact]
    public void TryParseProtocolVersionExchangeString_Valid()
    {
        const string sourceString = "!\"#$%&\'()*+,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
        var validCharBytes = Encoding.ASCII.GetBytes(sourceString);

        StringHelper.TryParseProtocolVersionExchangeString(validCharBytes, out var readString).Should().BeTrue();

        readString.Should().BeEquivalentTo(sourceString);
    }

    [Fact]
    public void TryParseProtocolVersionExchangeString_Invalid()
    {
        var testChars = new List<char>
            {
                ' ',
                '-',
                // Some random non US-ASCII chars
                'ä',
                '³'
            };

        for (var c = (char)0; c < 0x80; ++c)
        {
            if (char.IsControl(c))
            {
                testChars.Add(c);
            }
        }

        //Can hold every char in UTF-8
        Span<char> testCharSpan = stackalloc char[1];
        Span<byte> testBytesSpan = stackalloc byte[4];

        foreach (var testChar in testChars)
        {
            testCharSpan[0] = testChar;
            var len = Encoding.UTF8.GetBytes(testCharSpan, testBytesSpan);

            var inputBytes = testBytesSpan[0..len];
            StringHelper.TryParseProtocolVersionExchangeString(inputBytes, out var str).Should().BeFalse();
            str.Should().BeEmpty();
        }
    }
}
