using System;
using System.Collections.Generic;
using System.Linq;

namespace Slip39;

public record Share(
    ushort Id,
    bool Extendable,
    byte IterationExponent,
    byte GroupIndex,
    byte GroupThreshold,
    byte GroupCount,
    byte MemberIndex,
    byte MemberThreshold,
    byte[] Value)
{
    private static int Bits2Words(int n) => (n + RADIX_BITS - 1) / RADIX_BITS;
    internal const int ID_LENGTH_BITS = 15;
    private const int RADIX_BITS = 10;
    private static readonly int ID_EXP_LENGTH_WORDS = Bits2Words(ID_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS);
    private const int EXTENDABLE_FLAG_LENGTH_BITS = 1;
    private const int ITERATION_EXP_LENGTH_BITS = 4;
    private const int CHECKSUM_LENGTH_WORDS = 3;
    private static readonly int GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1;
    private static readonly int METADATA_LENGTH_WORDS = GROUP_PREFIX_LENGTH_WORDS + 1 + CHECKSUM_LENGTH_WORDS;
    private static readonly int MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + Bits2Words(Shamir.MinStrengthBits);

    public static Share FromMnemonic(string mnemonic)
    {
        var words = WordList.MnemonicToIndices(mnemonic);

        if (words.Length < MIN_MNEMONIC_LENGTH_WORDS)
        {
            throw new ArgumentException($"Invalid mnemonic length. The length of each mnemonic must be at least {MIN_MNEMONIC_LENGTH_WORDS} words.");
        }
        var prefix = WordsToBytes(words[..(GROUP_PREFIX_LENGTH_WORDS + 1)]);
        var prefixReader = new BitStreamReader(prefix);
        var id = prefixReader.ReadUint16(ID_LENGTH_BITS);
        var extendable = prefixReader.ReadUint8(EXTENDABLE_FLAG_LENGTH_BITS) == 1;

        if (Checksum(words, extendable) != 1)
        {
            throw new ArgumentException($"Invalid mnemonic checksum for \"{string.Join(" ", mnemonic.Split().Take(GROUP_PREFIX_LENGTH_WORDS + 1))} ...\".");
        }
        var paddingLen = RADIX_BITS * (words.Length - METADATA_LENGTH_WORDS) % 16;
        if (paddingLen > 8)
        {
            throw new ArgumentException("Invalid mnemonic length.");
        }

        var paddedValue = WordsToBytes(words[(GROUP_PREFIX_LENGTH_WORDS + 1)..^CHECKSUM_LENGTH_WORDS]);
        var valueReader = new BitStreamReader(paddedValue);
        if (valueReader.Read(paddingLen) != 0)
        {
            throw new ArgumentException("Invalid padding.");
        }

        var value = new List<byte>();
        while (valueReader.CanRead(8))
        {
            value.Add(valueReader.ReadUint8(8));
        }

        return new Share(
            Id: id,
            Extendable: extendable,
            IterationExponent: prefixReader.ReadUint8(ITERATION_EXP_LENGTH_BITS),
            GroupIndex: prefixReader.ReadUint8(4),
            GroupThreshold: (byte)(prefixReader.ReadUint8(4) + 1),
            GroupCount: (byte)(prefixReader.ReadUint8(4) + 1),
            MemberIndex: prefixReader.ReadUint8(4),
            MemberThreshold: (byte)(prefixReader.ReadUint8(4) + 1),
            Value: [.. value]
        );
    }

    public string ToMnemonic(string[] wordlist)
    {
        var prefixWriter = new BitStreamWriter();
        prefixWriter.Write(Id, ID_LENGTH_BITS);
        prefixWriter.Write(Extendable ? 1ul : 0, EXTENDABLE_FLAG_LENGTH_BITS);
        prefixWriter.Write(IterationExponent, ITERATION_EXP_LENGTH_BITS);
        prefixWriter.Write(GroupIndex, 4);
        prefixWriter.Write((byte)(GroupThreshold - 1), 4);
        prefixWriter.Write((byte)(GroupCount - 1), 4);
        prefixWriter.Write(MemberIndex, 4);
        prefixWriter.Write((byte)(MemberThreshold - 1), 4);
        var valueWordCount = (8 * Value.Length + RADIX_BITS - 1) / RADIX_BITS;
        var padding = valueWordCount * RADIX_BITS - Value.Length * 8;

        var valueWriter = new BitStreamWriter();
        valueWriter.Write(0, padding);
        foreach (var b in Value)
        {
            valueWriter.Write(b, 8);
        }

        var bytes = Utils.Concat(prefixWriter.ToByteArray(), valueWriter.ToByteArray());
        var words = Utils.Concat(BytesToWords(bytes), new ushort[] { 0, 0, 0 });
        var chk = Checksum(words, Extendable) ^ 1;
        var len = words.Length;
        for (var i = 0; i < 3; i++)
        {
            words[len - 3 + i] = (ushort)((chk >> (RADIX_BITS * (2 - i))) & 1023);
        }

        return string.Join(" ", words.Select(i => wordlist[i]));
    }

    private static ushort[] BytesToWords(byte[] bytes)
    {
        var words = new List<ushort>();
        var reader = new BitStreamReader(bytes);
        while (!reader.EndOdStream)
        {
            words.Add(reader.ReadUint16(10));
        }

        return [.. words];
    }

    private static byte[] WordsToBytes(ushort[] words)
    {
        var writer = new BitStreamWriter();

        foreach (var word in words)
        {
            writer.Write(word, 10);
        }

        return writer.ToByteArray();
    }

    private static readonly byte[] CustomizationStringOrig = "shamir"u8.ToArray();
    private static readonly byte[] CustomizationStringExtendable = "shamir_extendable"u8.ToArray();
    private static int Checksum(ushort[] values, bool extendable)
    {
        var gen = new[]{
        0x00E0E040, 0x01C1C080, 0x03838100, 0x07070200, 0x0E0E0009,
        0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x03F3F120,
    };

        var chk = 1;
        var customizationString = extendable ? CustomizationStringExtendable : CustomizationStringOrig;
        foreach (var v in customizationString.Select(x => (ushort)x).Concat(values))
        {
            var b = chk >> 20;
            chk = ((chk & 0xFFFFF) << 10) ^ v;
            for (var i = 0; i < 10; i++)
            {
                chk ^= ((b >> i) & 1) != 0 ? gen[i] : 0;
            }
        }

        return chk;
    }
}
