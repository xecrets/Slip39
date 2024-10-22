using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Group = (int memberThreshold, int count);
using ShareData = (int memberIndex, byte[] value);

namespace Slip39;

/// <summary>
/// A class for implementing Shamir's Secret Sharing with SLIP-39 enhancements.
/// </summary>
public class Shamir
{
    private record MemberData(int MemberThreshold, int MemberIndex, byte[] Value);

    private record CommonParameters(int Id, int IterationExponent, int GroupThreshold, Dictionary<int, List<MemberData>> Groups);

    private const int SECRET_INDEX = 255;
    private const int DIGEST_INDEX = 254;
    private const int MAX_SHARE_COUNT = 16;
    private const int DIGEST_LENGTH_BYTES = 4;
    private const int BASE_ITERATION_COUNT = 10000;
    private const int ROUND_COUNT = 4;

    public static int MinStrengthBits => 128;

    public static Share[] Generate(
        IRandom random,
        int memberThreshold,
        int memberCount,
        byte[] seed,
        string passphrase = "",
        int iterationExponent = 0,
        bool extendable = true) => 
            Generate(random, 1, [new Group(memberThreshold, memberCount)], seed, passphrase, iterationExponent, extendable);

    /// <summary>
    /// Generates SLIP-39 shares from a given seed.
    /// </summary>
    /// <param name="groupThreshold">The number of groups required to reconstruct the secret.</param>
    /// <param name="groups">Array of tuples where each tuple represents (groupThreshold, shareCount) for each group.</param>
    /// <param name="seed">The secret to be split into shares.</param>
    /// <param name="passphrase">The passphrase used for encryption.</param>
    /// <param name="iterationExponent">Exponent to determine the number of iterations for the encryption algorithm.</param>
    /// <param name="extendable"></param>
    /// <returns>A list of shares that can be used to reconstruct the secret.</returns>
    /// <exception cref="ArgumentException">Thrown when inputs do not meet the required constraints.</exception>
    public static Share[] Generate(
        IRandom random,
        int groupThreshold,
        Group[] groups,
        byte[] seed,
        string passphrase = "",
        int iterationExponent = 0,
        bool extendable = true)
    {
        var secret = seed;
        // Validating seed strength and format
        if (secret.Length * 8 < MinStrengthBits || secret.Length % 2 != 0)
        {
            throw new ArgumentException("master key entropy must be at least 128 bits and multiple of 16 bits");
        }

        // Validating group constraints
        if (groupThreshold > MAX_SHARE_COUNT)
        {
            throw new ArgumentException("more than 16 groups are not supported");
        }

        if (groupThreshold > groups.Length)
        {
            throw new ArgumentException("group threshold should not exceed number of groups");
        }

        if (groups.Any(group => group is { memberThreshold: 1, count: > 1 }))
        {
            throw new ArgumentException("can only generate one share for threshold = 1");
        }

        if (groups.Any(group => group.memberThreshold > group.count))
        {
            throw new ArgumentException("number of shares must not be less than threshold");
        }

        // Generate a random identifier
        var id = (ushort)(BitConverter.ToUInt32(random.GetBytes(4)) % ((1 << (Share.ID_LENGTH_BITS + 1)) - 1));
        var shares = new List<Share>();

        // Encrypt the secret using the passphrase and identifier
        var encryptedSecret = Encrypt(id, iterationExponent, secret, passphrase, extendable);

        // Split the encrypted secret into group shares
        var groupShares = SplitSecret(
            random,
            groupThreshold,
            (byte)groups.Length,
            encryptedSecret);

        // Split each group share into member shares and create the final share objects
        foreach (var (groupIndex, groupShare) in groupShares)
        {
            var (memberThreshold, count) = groups[groupIndex];

            var memberShares = SplitSecret(random, memberThreshold, count, groupShare);
            foreach (var (memberIndex, value) in memberShares)
            {
                shares.Add(new Share(
                     id,
                     extendable,
                     iterationExponent,
                     groupIndex,
                     groupThreshold,
                     (byte)groups.Length,
                     memberIndex,
                     memberThreshold,
                     value));
            }
        }

        return [.. shares];
    }

    /// <summary>
    /// Combines shares to reconstruct the original secret.
    /// </summary>
    /// <param name="shares">The array of shares to combine.</param>
    /// <param name="passphrase">The passphrase used for decrypting the shares.</param>
    /// <param name="extendable"></param>
    /// <returns>The reconstructed secret.</returns>
    /// <exception cref="ArgumentException">Thrown when the shares are insufficient or invalid.</exception>
    public static byte[] Combine(Share[] shares, string passphrase = "")
    {
        // Preprocess the shares to extract group and member information
        CommonParameters common = Preprocess(shares);

        // Validating group constraints 
        if (common.Groups.Count < common.GroupThreshold)
        {
            throw new ArgumentException("need shares from more groups to reconstruct secret");
        }

        if (common.Groups.Count != common.GroupThreshold)
        {
            throw new ArgumentException("shares from too many groups");
        }

        if (common.Groups.Any(group => group.Value[0].MemberThreshold != group.Value.Count))
        {
            throw new ArgumentException("for every group, number of member shares should match member threshold");
        }

        if (common.Groups.Any(group => group.Value.Select(v => v.MemberThreshold).ToHashSet().Count > 1))
        {
            throw new ArgumentException("member threshold must be the same within a group");
        }

        // Recover secrets for each group and then combine them to get the final secret
        var groupSecrets = new List<ShareData>();
        foreach (var group in common.Groups)
        {
            var recoveredSecret = RecoverSecret(group.Value[0].MemberThreshold, group.Value.Select(v => (v.MemberIndex, v.Value)).ToArray());
            groupSecrets.Add((group.Key, recoveredSecret));
        }

        var finalRecoveredSecret = RecoverSecret(common.GroupThreshold, [.. groupSecrets]);

        // Decrypt the secret using the passphrase
        var decryptedSeed = Decrypt(common.Id, common.IterationExponent, finalRecoveredSecret, passphrase, shares[0].Extendable);
        return decryptedSeed;
    }

    /// <summary>
    /// Preprocesses the shares to group them by group index and validate constraints.
    /// </summary>
    /// <param name="shares">The array of shares to preprocess.</param>
    /// <returns>A tuple containing identifiers and group information for the shares.</returns>
    /// <exception cref="ArgumentException">Thrown when the shares do not meet the required constraints.</exception>
    private static CommonParameters Preprocess(Share[] shares)
    {
        if (shares.Length < 1)
        {
            throw new ArgumentException("need at least one share to reconstruct secret");
        }

        // Ensure all shares belong to the same secret
        var identifiers = shares.Select(s => s.Id).ToHashSet();
        if (identifiers.Count > 1)
        {
            throw new ArgumentException("shares do not belong to the same secret");
        }

        // Ensure all shares have the same iteration exponent, group threshold, and group count
        var iterationExponents = shares.Select(s => s.IterationExponent).ToHashSet();
        if (iterationExponents.Count > 1)
        {
            throw new ArgumentException("shares do not have the same iteration exponent");
        }

        var groupThresholds = shares.Select(s => s.GroupThreshold).ToHashSet();
        if (groupThresholds.Count > 1)
        {
            throw new ArgumentException("shares do not have the same group threshold");
        }

        var groupCounts = shares.Select(s => s.GroupCount).ToHashSet();
        if (groupCounts.Count > 1)
        {
            throw new ArgumentException("shares do not have the same group count");
        }

        if (shares.Any(s => s.GroupThreshold > s.GroupCount))
        {
            throw new ArgumentException("greater group threshold than group counts");
        }

        // Group the shares by group index
        var groups = new Dictionary<int, List<MemberData>>();
        foreach (Share share in shares)
        {
            if (!groups.TryGetValue(share.GroupIndex, out var value))
            {
                value = [];
                groups[share.GroupIndex] = value;
            }

            value.Add(new MemberData(MemberThreshold: share.MemberThreshold, MemberIndex: share.MemberIndex, Value: [.. share.Value]));
        }

        return new CommonParameters(Id: identifiers.First(), IterationExponent: iterationExponents.First(),
            GroupThreshold: groupThresholds.First(), groups);
    }

    /// <summary>
    /// Recovers the secret from a set of shares.
    /// </summary>
    /// <param name="threshold">The number of shares required to reconstruct the secret.</param>
    /// <param name="shares">The shares to be used for reconstruction.</param>
    /// <returns>The recovered secret.</returns>
    /// <exception cref="ArgumentException">Thrown when the share digests are incorrect.</exception>
    public static byte[] RecoverSecret(int threshold, ShareData[] shares)
    {
        // If the threshold is 1, simply return the first share's value
        if (threshold == 1)
        {
            return shares[0].value;
        }

        // Interpolate the shares to recover the shared secret and digest
        var sharedSecret = Interpolate(shares, SECRET_INDEX);
        var digestShare = Interpolate(shares, DIGEST_INDEX);

        // Verify the share digest. (poor-man constant-time comparison)
        return BitConverter.ToUInt32(ShareDigest(digestShare[DIGEST_LENGTH_BYTES..], sharedSecret)) !=
            BitConverter.ToUInt32(digestShare.AsSpan()[..DIGEST_LENGTH_BYTES])
                ? throw new ArgumentException("share digest incorrect")
                : sharedSecret;
    }

    private static ShareData[] SplitSecret(IRandom random, int threshold, int shareCount, byte[] sharedSecret)
    {
        if (threshold < 1)
        {
            throw new ArgumentException("sharing threshold must be > 1");
        }

        if (shareCount > MAX_SHARE_COUNT)
        {
            throw new ArgumentException("too many shares");
        }

        if (threshold > shareCount)
        {
            throw new ArgumentException("number of shares should be at least equal threshold");
        }

        var shares = new List<ShareData>();

        if (threshold == 1)
        {
            for (byte i = 0; i < shareCount; i++)
            {
                shares.Add((i, sharedSecret.ToArray()));
            }
            return [.. shares];
        }

        int randomSharesCount = Math.Max(threshold - 2, 0);

        for (byte i = 0; i < randomSharesCount; i++)
        {
            var share = new byte[sharedSecret.Length];
            random.GetBytes(share);
            shares.Add((i, share));
        }

        var baseShares = new List<ShareData>(shares);
        var randomPart = new byte[sharedSecret.Length - DIGEST_LENGTH_BYTES];
        random.GetBytes(randomPart);

        var digest = ShareDigest(randomPart, sharedSecret);
        baseShares.Add((DIGEST_INDEX, Utils.Concat(digest, randomPart)));
        baseShares.Add((SECRET_INDEX, sharedSecret));

        for (byte i = (byte)randomSharesCount; i < shareCount; i++)
        {
            var interpolatedShare = Interpolate([.. baseShares], i);
            shares.Add((i, interpolatedShare));
        }

        return [.. shares];
    }

    private static byte[] ShareDigest(byte[] random, byte[] sharedSecret)
    {
        using var hmac = new HMACSHA256(random);
        var hash = hmac.ComputeHash(sharedSecret);
        return hash[..4];
    }

    /// <summary>
    /// Interpolates the shares to recover the secret.
    /// </summary>
    /// <param name="shares">The shares used for interpolation.</param>
    /// <param name="x">The index of the value to interpolate (secret or digest).</param>
    /// <returns>The interpolated value.</returns>
    private static byte[] Interpolate(ShareData[] shares, byte x)
    {
        var xCoordinates = shares.Select(share => share.memberIndex).ToHashSet();
        if (xCoordinates.Count != shares.Length)
        {
            throw new ArgumentException("need unique shares for interpolation");
        }
        if (shares.Length < 1)
        {
            throw new ArgumentException("need at least one share for interpolation");
        }
        var len = shares[0].value.Length;
        if (shares.Any(share => share.value.Length != len))
        {
            throw new ArgumentException("shares should have equal length");
        }
        if (xCoordinates.Contains(x))
        {
            return shares.First(share => share.memberIndex == x).value;
        }

        static int Mod255(int n)
        {
            while (n < 0) n += 255;
            return n % 255;
        }

        int logProd = shares
            .Select(share => Log[share.memberIndex ^ x])
            .Aggregate(0, (a, v) => a + v);

        var result = new byte[len];
        foreach (var (i, share) in shares)
        {
            var logBasis = Mod255(
                logProd - Log[i ^ x]
                        - shares.Select(j => Log[j.memberIndex ^ i]).Aggregate(0, (a, v) => a + v)
            );

            for (var k = 0; k < share.Length; k++)
            {
                result[k] ^= share[k] != 0 ? Exp[Mod255(Log[share[k]] + logBasis)] : (byte)0;
            }
        }

        return result;
    }

    private static byte[] Encrypt(ushort identifier, int iterationExponent, byte[] master, string passphrase, bool extendable) =>
        Crypt(identifier, iterationExponent, master, [0, 1, 2, 3], CheckPassphrase(passphrase), extendable);

    private static byte[] Decrypt(int identifier, int iterationExponent, byte[] master, string passphrase, bool extendable) =>
        Crypt(identifier, iterationExponent, master, [3, 2, 1, 0], CheckPassphrase(passphrase), extendable);

    private static string CheckPassphrase(string passphrase) =>
        passphrase.Any(Char.IsControl)
            ? throw new NotSupportedException("Passphrase should only contain printable ASCII.")
            : passphrase;

    private static byte[] Crypt(
        int identifier,
        int iterationExponent,
        byte[] masterSecret,
        byte[] range,
        string passphrase,
        bool extendable)
    {
        var len = masterSecret.Length / 2;
        var left = masterSecret[..len];
        var right = masterSecret[len..];
        foreach (var i in range)
        {
            var f = Feistel(identifier, iterationExponent, i, right, passphrase, extendable);
            (left, right) = (right, Xor(left, f));
        }
        return Utils.Concat(right, left);
    }

    private static byte[] Feistel(int id, int iterationExponent, byte step, byte[] block, string passphrase, bool extendable)
    {
        var key = Utils.Concat([step], Encoding.UTF8.GetBytes(passphrase));
        var saltPrefix = extendable ? [] : Utils.Concat("shamir"u8.ToArray(), [(byte)(id >> 8), (byte)(id & 0xff)]);
        var salt = Utils.Concat(saltPrefix, block);
        var iters = (BASE_ITERATION_COUNT / ROUND_COUNT) << iterationExponent;
        using var pbkdf2 = new Rfc2898DeriveBytes(key, salt, iters, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(block.Length);
    }

    private static byte[] Xor(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }

    private static readonly byte[] Exp = [
        1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216,
        115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106,
        190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211,
        110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131,
        158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87,
        249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173,
        236, 47, 113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50,
        86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218,
        117, 159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155,
        182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165,
        244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168,
        227, 62, 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167,
        242, 13, 23, 57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246,
    ];
    private static readonly byte[] Log = [
        0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141,
        129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77,
        228, 166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53,
        147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56,
        102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126, 110, 72, 195,
        163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202,
        78, 212, 172, 229, 243, 115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233,
        213, 231, 230, 173, 232, 44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169,
        81, 160, 127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204,
        187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97,
        190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20,
        42, 158, 93, 86, 242, 211, 171, 68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119,
        153, 227, 165, 103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7,
    ];
}
