using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Xunit;

namespace Slip39.Test;

public class TestVectors
{
    [Theory]
    [MemberData(nameof(Slip39TestVector.TestCasesData), MemberType = typeof(Slip39TestVector))]
    public void TestAllVectors(Slip39TestVector test)
    {
        if (!string.IsNullOrEmpty(test.SecretHex))
        {
            Share[] shares = test.Mnemonics.Select(Share.FromMnemonic).ToArray();
            byte[] secret = Shamir.Combine(shares, "TREZOR");
            Assert.Equal(test.SecretHex, Convert.ToHexString(secret).ToLower());

            //Assert.Equal(new BIP32Key(secret).ExtendedKey(), xprv);
        }
        else
        {
            Assert.Throws<ArgumentException>((Action)(() =>
            {
                var shares = test.Mnemonics.Select(Share.FromMnemonic).ToArray();
                Shamir.Combine((Share[])shares);
                Assert.Fail($"Failed to raise exception for test vector \"{test.Description}\".");
            }));
        }
    }
}

public record Slip39TestVector(string Description, string[] Mnemonics, string SecretHex, string Xprv)
{
    private static IEnumerable<Slip39TestVector> VectorsData()
    {
        string vectorsJson = File.ReadAllText("vectors.json");
        var vectors = JsonConvert.DeserializeObject<IEnumerable<object[]>>(vectorsJson)
            ?? throw new InvalidOperationException("Deserialization of 'vectors.json' failed.");
        foreach (var x in vectors)
        {
            yield return new(
                Description: (string)x[0],
                Mnemonics: ((JArray)x[1]).Values<string>().Cast<string>().ToArray(),
                SecretHex: (string)x[2],
                Xprv: (string)x[3]
            );
        }
    }

    private static readonly Slip39TestVector[] TestCases = VectorsData().ToArray();

    public static TheoryData<Slip39TestVector> TestCasesData => new TheoryData<Slip39TestVector>(TestCases);

    public override string ToString() => Description;
}
