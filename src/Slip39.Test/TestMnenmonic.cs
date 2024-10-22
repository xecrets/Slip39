using System.Diagnostics;

using Xunit;

namespace Slip39.Test;

public class TestMnenmonic
{
    private static readonly byte[] _masterSecret = "ABCDEFGHIJKLMNOP"u8.ToArray();

    private static readonly string[] mnemonics =
    {
        "vocal again academic acne both insect modern making forbid grief flavor faint intimate senior priority satoshi aunt screw finance silent",
        "vocal again academic agree alive race acne husky priority skunk salt device taught hearing mama scout marvel daisy justice wits",
        "vocal again academic amazing ambition window equip paid amuse knife family intimate yoga destroy greatest retreat step finance funding client",
        "vocal again academic arcade breathe domain style greatest work spend secret believe hamster museum elephant render forward reunion hush benefit",
        "vocal again academic axle careful cylinder impact parking shrimp ancient forget element domestic package flavor morning glimpse visual says device"
    };

    [Fact]
    public void TestGenerateMnemonics()
    {
        FakeRandom random = new();

        Share[] shares = Shamir.Generate(random, 3, 5, _masterSecret);
        Assert.Equal(mnemonics.Length, shares.Length);
        for (int i = 0; i < shares.Length; ++i)
        {
            //Debug.WriteLine(shares[i].ToMnemonic(WordList.Wordlist));
            Assert.Equal(mnemonics[i], shares[i].ToMnemonic(WordList.Wordlist));
        }

        for (int i = 0; i < shares.Length; ++i)
        {
            Share share = Share.FromMnemonic(mnemonics[i]);
            Assert.True(share.Value.SequenceEqual(shares[i].Value));
        }
    }
}
