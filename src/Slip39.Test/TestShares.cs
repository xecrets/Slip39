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
        Share[] shares = Shamir.Generate(random, 1, [new Group(3, 5)], secret);
        Assert.Equal(
            Shamir.Combine(shares[..3]),
            Shamir.Combine(shares[2..])
        );
    }

    [Fact]
    public void TestBasicSharingFixed()
    {
        FakeRandom random = new();

        Share[] shares = Shamir.Generate(random, 1, [new Group(3, 5)], MS);
        Assert.Equal(MS, Shamir.Combine(shares[..3]));
        Assert.Equal(MS, Shamir.Combine(shares[1..4]));
        Assert.Throws<ArgumentException>(() =>
            Shamir.Combine(shares[..2])
        );
    }

    [Fact]
    public void TestPassphrase()
    {
        FakeRandom random = new();

        Share[] shares = Shamir.Generate(random, 1, [new Group(3, 5)], MS, "TREZOR");
        Assert.Equal(MS, Shamir.Combine(shares[1..4], "TREZOR"));
        Assert.NotEqual(MS, Shamir.Combine(shares[1..4]));
    }

    [Fact]
    public void TestNonExtendable()
    {
        FakeRandom random = new();

        Share[] shares = Shamir.Generate(random, 1, [new Group(3, 5)], MS, extendable: false);
        Assert.Equal(MS, Shamir.Combine(shares[1..4]));
    }

    [Fact]
    public void TestIterationExponent()
    {
        FakeRandom random = new();

        Share[] shares = Shamir.Generate(random, 1, [new Group(3, 5)], MS, "TREZOR", iterationExponent: 1);
        Assert.Equal(MS, Shamir.Combine(shares[1..4], "TREZOR"));
        Assert.NotEqual(MS, Shamir.Combine(shares[1..4]));

        shares = Shamir.Generate(random, 1, [new Group(3, 5)], MS, "TREZOR", iterationExponent: 2);
        Assert.Equal(MS, Shamir.Combine(shares[1..4], "TREZOR"));
        Assert.NotEqual(MS, Shamir.Combine(shares[1..4]));
    }

    [Fact]
    public void TestGroupSharing()
    {
        FakeRandom random = new();

        int groupThreshold = 2;
        Group[] groups = [new Group(3, 5), new Group(2, 3), new Group(2, 5), new Group(1, 1),];
        Share[] shares = Shamir.Generate(random, groupThreshold, groups, MS);
        Share[][] shareGroupings = shares.GroupBy(x => x.GroupIndex).Select(x => x.ToArray()).ToArray();

        // Test all valid combinations of mnemonics.
        foreach ((Share[] shares, int memberThreshold)[] combinations in
            Combinations(shareGroupings.Zip(groups.Select(g => g.memberThreshold)), groupThreshold))
        {
            foreach (Share[] group1Subset in Combinations(combinations[0].shares, combinations[0].memberThreshold))
            {
                foreach (Share[] group2Subset in Combinations(combinations[1].shares, combinations[1].memberThreshold))
                {
                    Share[] shareSubset = group1Subset.Concat(group2Subset);
                    shareSubset = [.. shareSubset.OrderBy(x => Guid.NewGuid())];
                    Assert.Equal(MS, Shamir.Combine(shareSubset));
                }
            }
        }

        Assert.Equal(MS, Shamir.Combine([shareGroupings[2][0], shareGroupings[2][2], shareGroupings[3][0]]));
        Assert.Equal(MS, Shamir.Combine([shareGroupings[2][3], shareGroupings[3][0], shareGroupings[2][4]]));

        Assert.Throws<ArgumentException>(() =>
            Shamir.Combine(shareGroupings[0][2..].Concat(shareGroupings[1][..1]))
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Combine(shareGroupings[0][1..4])
        );
    }

    [Fact]
    public void TestGroupSharingThreshold1()
    {
        FakeRandom random = new();

        int groupThreshold = 1;
        int[] groupSizes = [5, 3, 5, 1];
        int[] memberThresholds = [3, 2, 2, 1];

        Group[] groups = [new Group(3, 5), new Group(2, 3), new Group(2, 5), new Group(1, 1),];
        Share[] shares = Shamir.Generate(random, groupThreshold, groups, MS);
        Share[][] shareGroupings = shares.GroupBy(x => x.GroupIndex).Select(x => x.ToArray()).ToArray();

        foreach ((Share[] groupShares, int memberThreshold) in shareGroupings.Zip(groups.Select(g => g.memberThreshold)))
        {
            foreach (Share[] groupSubset in Combinations(groupShares, memberThreshold))
            {
                Share[] shareSubset = [.. groupSubset.OrderBy(_ => Guid.NewGuid())];
                Assert.Equal(MS, Shamir.Combine(shareSubset));
            }
        }
    }

    [Fact]
    public void TestAllGroupsExist()
    {
        FakeRandom random = new();

        Group[] groups = [new Group(3, 5), new Group(1, 1), new Group(2, 3), new Group(2, 5), new Group(3, 5),];

        foreach (int groupThreshold in new int[] { 1, 2, 5 })
        {
            Share[] shares = Shamir.Generate(random, groupThreshold, groups, MS);
            Share[][] shareGroupings = shares.GroupBy(x => x.GroupIndex).Select(x => x.ToArray()).ToArray();
            Assert.Equal(5, shareGroupings.Length);
            Assert.Equal(19, shareGroupings.Sum(g => g.Length));
        }
    }

    [Fact]
    public void TestInvalidSharing()
    {
        FakeRandom random = new();

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 1, [new Group(2, 3)], MS.Take(14).ToArray())
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 1, [new Group(2, 3)], [.. MS, .. "X"u8.ToArray()])
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 3, [new Group(3, 5), new Group(2, 5)], MS)
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 0, [new Group(3, 5), new Group(2, 5)], MS)
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 2, [new Group(3, 2), new Group(2, 5)], MS)
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 2, [new Group(0, 2), new Group(2, 5)], MS)
        );

        Assert.Throws<ArgumentException>(() =>
            Shamir.Generate(random, 2, [new Group(3, 5), new Group(1, 3), new Group(2, 5)], MS)
        );
    }

    private static T[][] Combinations<T>(IEnumerable<T> iterable, int r)
    {
        IEnumerable<IEnumerable<T>> InternalCombinations()
        {
            T[] pool = iterable.ToArray();
            int n = pool.Length;
            if (r > n) yield break;

            int[] indices = Enumerable.Range(0, r).ToArray();

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
