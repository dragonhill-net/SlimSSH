using Dragonhill.SlimSSH.Exceptions;
using System.Security.Cryptography;

namespace Dragonhill.SlimSSH.Helpers;

public static class PaddingHelper
{
    public static byte CalculatePaddingLength(int lengthOfContent, int blockSize)
    {
        var paddingAmount = blockSize - lengthOfContent % blockSize;
        if (paddingAmount < Constants.MinPaddingLength)
        {
            paddingAmount += blockSize;
        }

        if (paddingAmount > byte.MaxValue)
        {
            SshExceptionThrowHelper.ArgumentOutOfRange(nameof(blockSize));
        }

        return (byte)paddingAmount;
    }

    public static byte CalculateAndRandomFillPadding(Span<byte> paddingTarget, int currentUsedLength, int blockSize)
    {
        var paddingAmount = CalculatePaddingLength(currentUsedLength, blockSize);

        RandomNumberGenerator.Fill(paddingTarget[..paddingAmount]);

        return paddingAmount;
    }
}
