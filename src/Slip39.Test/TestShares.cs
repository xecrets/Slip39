using Xunit;

namespace Slip39.Test;

public class TestShares
{
    private static readonly byte[] MS = "ABCDEFGHIJKLMNOP"u8.ToArray();

    [Fact]
    public void TestBasicSharingRandom()
    {
        FakeRandom random = new();

        byte[] secret = new byte[16];
        random.GetBytes(secret);
        var mnemonics = Shamir.Generate(random, 1, [(3, 5)], secret);
        Assert.Equal(
            Shamir.Combine(mnemonics[..3]),
            Shamir.Combine(mnemonics[2..])
        );
    }

    [Fact]
    public void TestBasicSharingFixed()
    {
        FakeRandom random = new();

        var mnemonics = Shamir.Generate(random, 1, [(3, 5)], MS);
        Assert.Equal(MS, Shamir.Combine(mnemonics[..3]));
        Assert.Equal(MS, Shamir.Combine(mnemonics[1..4]));
        Assert.Throws<ArgumentException>(() =>
            Shamir.Combine(mnemonics[..2])
        );
    }

    [Fact]
    public void TestPassphrase()
    {
        FakeRandom random = new();

        var mnemonics = Shamir.Generate(random, 1, [(3, 5)], MS, "TREZOR");
        Assert.Equal(MS, Shamir.Combine(mnemonics[1..4], "TREZOR"));
        Assert.NotEqual(MS, Shamir.Combine(mnemonics[1..4]));
    }

    [Fact]
    public void TestNonExtendable()
    {
        FakeRandom random = new();

        var mnemonics = Shamir.Generate(random, 1, [(3, 5)], MS, extendable: false);
        Assert.Equal(MS, Shamir.Combine(mnemonics[1..4]));
    }

    [Fact]
    public void TestIterationExponent()
    {
        FakeRandom random = new();

        var mnemonics = Shamir.Generate(random, 1, [(3, 5)], MS, "TREZOR", iterationExponent: 1);
        Assert.Equal(MS, Shamir.Combine(mnemonics[1..4], "TREZOR"));
        Assert.NotEqual(MS, Shamir.Combine(mnemonics[1..4]));

        mnemonics = Shamir.Generate(random, 1, [(3, 5)], MS, "TREZOR", iterationExponent: 2);
        Assert.Equal(MS, Shamir.Combine(mnemonics[1..4], "TREZOR"));
        Assert.NotEqual(MS, Shamir.Combine(mnemonics[1..4]));
    }

    [Fact]
    public void TestGroupSharing()
    {
        FakeRandom random = new();

        int groupThreshold = 2;
        int[] groupSizes = [5, 3, 5, 1];
        int[] memberThresholds = [3, 2, 2, 1];
        var shares = Shamir.Generate(random, groupThreshold, memberThresholds.Zip(groupSizes).ToArray(), MS);
        var mnemonics = shares.GroupBy(x => x.GroupIndex).Select(x => x.ToArray()).ToArray();

        // Test all valid combinations of mnemonics.
        foreach (var groups in Combinations(mnemonics.Zip(memberThresholds, (a, b) => (Shares: a, MemberThreshold: b)),
                     groupThreshold))
        {
            foreach (var group1Subset in Combinations(groups[0].Shares, groups[0].MemberThreshold))
            {
                foreach (var group2Subset in Combinations(groups[1].Shares, groups[1].MemberThreshold))
                {
                    var mnemonicSubset = Utils.Concat(group1Subset, group2Subset);
                    mnemonicSubset = [.. mnemonicSubset.OrderBy(x => Guid.NewGuid())];
                    Assert.Equal(MS, Shamir.Combine(mnemonicSubset));
                }
            }
        }

        Assert.Equal(MS, Shamir.Combine([mnemonics[2][0], mnemonics[2][2], mnemonics[3][0]]));
        Assert.Equal(MS, Shamir.Combine([mnemonics[2][3], mnemonics[3][0], mnemonics[2][4]]));

        Assert.Throws<ArgumentException>(() =>
            Shamir.Combine(Utils.Concat(mnemonics[0][2..], mnemonics[1][..1]))
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Combine(mnemonics[0][1..4])
        );
    }

    [Fact]
    public void TestGroupSharingThreshold1()
    {
        FakeRandom random = new();

        int groupThreshold = 1;
        int[] groupSizes = [5, 3, 5, 1];
        int[] memberThresholds = [3, 2, 2, 1];
        var shares = Shamir.Generate(random, groupThreshold, memberThresholds.Zip(groupSizes).ToArray(), MS);
        var mnemonics = shares.GroupBy(x => x.GroupIndex).Select(x => x.ToArray()).ToArray();

        foreach (var (group, memberThreshold) in mnemonics.Zip(memberThresholds, (g, t) => (g, t)))
        {
            foreach (var groupSubset in Combinations(group, memberThreshold))
            {
                var mnemonicSubset = groupSubset.OrderBy(_ => Guid.NewGuid()).ToArray();
                Assert.Equal(MS, Shamir.Combine(mnemonicSubset));
            }
        }
    }

    [Fact]
    public void TestAllGroupsExist()
    {
        FakeRandom random = new();

        foreach (var groupThreshold in new byte[] { 1, 2, 5 })
        {
            var shares = Shamir.Generate(random, groupThreshold, [(3, 5), (1, 1), (2, 3), (2, 5), (3, 5)], MS);
            var mnemonics = shares.GroupBy(x => x.GroupIndex).Select(x => x.ToArray()).ToArray();
            Assert.Equal(5, mnemonics.Length);
            Assert.Equal(19, mnemonics.Sum(g => g.Length));
        }
    }

    [Fact]
    public void TestInvalidSharing()
    {
        FakeRandom random = new();

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 1, [(2, 3)], MS.Take(14).ToArray())
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 1, [(2, 3)], [.. MS, .. "X"u8.ToArray()])
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 3, [(3, 5), (2, 5)], MS)
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 0, [(3, 5), (2, 5)], MS)
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 2, [(3, 2), (2, 5)], MS)
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 2, [(0, 2), (2, 5)], MS)
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 2, [(3, 5), (1, 3), (2, 5)], MS)
        );
    }

    public static T[][] Combinations<T>(IEnumerable<T> iterable, int r)
    {
        IEnumerable<IEnumerable<T>> InternalCombinations()
        {
            var pool = iterable.ToArray();
            int n = pool.Length;
            if (r > n) yield break;

            var indices = Enumerable.Range(0, r).ToArray();

            yield return indices.Select(i => pool[i]);

            while (true)
            {
                int i;
                for (i = r - 1; i >= 0; i--)
                {
                    if (indices[i] != i + n - r)
                    {
                        break;
                    }
                }

                if (i < 0) yield break;

                indices[i]++;
                for (int j = i + 1; j < r; j++)
                {
                    indices[j] = indices[j - 1] + 1;
                }

                yield return indices.Select(index => pool[index]);
            }
        }

        return InternalCombinations().Select(x => x.ToArray()).ToArray();
    }
}
