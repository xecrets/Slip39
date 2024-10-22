using Xunit;

namespace Slip39.Test;

public class TestMnenmonic
{
    private static readonly byte[] _masterSecret = "ABCDEFGHIJKLMNOP"u8.ToArray();

    [Fact]
    public void TestGenerateMnemonics()
    {
        FakeRandom random = new();

        Share[] shares = Shamir.Generate(random, 3, 5, _masterSecret);
    }
}
