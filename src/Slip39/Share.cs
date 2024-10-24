#region Copyright and MIT License
/* MIT License
 *
 * Copyright © 2024 Lucas Ontivero
 * 
 * Modifications Copyright © 2024 Svante Seleborg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/
#endregion Copyright and MIT License

using System;
using System.Collections.Generic;
using System.Linq;

namespace Slip39;

public class Share
{
    private const int ID_LENGTH_BITS = 15;
    private const int RADIX_BITS = 10;
    private const int ID_EXP_LENGTH_WORDS = (ID_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS + RADIX_BITS - 1) / RADIX_BITS;
    private const int EXTENDABLE_FLAG_LENGTH_BITS = 1;
    private const int ITERATION_EXP_LENGTH_BITS = 4;
    private const int CHECKSUM_LENGTH_WORDS = 3;
    private const int GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1;
    private const int METADATA_LENGTH_WORDS = GROUP_PREFIX_LENGTH_WORDS + 1 + CHECKSUM_LENGTH_WORDS;
    private const int MIN_STRENGTH_BITS = 128;
    private const int MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + ((MIN_STRENGTH_BITS + RADIX_BITS - 1) / RADIX_BITS);

    public static int MinStrengthBits => MIN_STRENGTH_BITS;

    public int Id { get; }
    public bool Extendable { get; }
    public int IterationExponent { get; }
    public int GroupIndex { get; }
    public int GroupThreshold { get; }
    public int GroupCount { get; }
    public int MemberIndex { get; }
    public int MemberThreshold { get; }
    public byte[] Value { get; }

    private Share(int id, bool extendable, int iterationExponent, int groupIndex, Group group,
        int memberIndex, int memberThreshold, byte[] value)
    {
        Id = id;
        Extendable = extendable;
        IterationExponent = iterationExponent;
        GroupIndex = groupIndex;
        GroupThreshold = group.MemberThreshold;
        GroupCount = group.Count;
        MemberIndex = memberIndex;
        MemberThreshold = memberThreshold;
        Value = value;
    }

    public static Share Create(int id, bool extendable, int iterationExponent, int groupIndex, Group group,
        int memberIndex, int memberThreshold, byte[] value)
    {
        return new Share(id, extendable, iterationExponent, groupIndex, group, memberIndex, memberThreshold, value);
    }

    public static Share FromMnemonic(string mnemonic)
    {
        int[] words = WordList.MnemonicToIndices(mnemonic);

        if (words.Length < MIN_MNEMONIC_LENGTH_WORDS)
        {
            throw new ArgumentException($"Invalid mnemonic length. The length of each mnemonic must be at least {MIN_MNEMONIC_LENGTH_WORDS} words.");
        }
        byte[] prefix = WordsToBytes(words[..(GROUP_PREFIX_LENGTH_WORDS + 1)]);
        BitStreamReader prefixReader = new(prefix);
        int id = prefixReader.Read(ID_LENGTH_BITS);
        bool extendable = prefixReader.Read(EXTENDABLE_FLAG_LENGTH_BITS) == 1;

        if (Checksum(words, extendable) != 1)
        {
            throw new ArgumentException($"Invalid mnemonic checksum for \"{string.Join(" ", mnemonic.Split().Take(GROUP_PREFIX_LENGTH_WORDS + 1))} ...\".");
        }
        int paddingLen = RADIX_BITS * (words.Length - METADATA_LENGTH_WORDS) % 16;
        if (paddingLen > 8)
        {
            throw new ArgumentException("Invalid padding length.");
        }

        byte[] paddedValue = WordsToBytes(words[(GROUP_PREFIX_LENGTH_WORDS + 1)..^CHECKSUM_LENGTH_WORDS]);
        BitStreamReader valueReader = new(paddedValue);
        if (valueReader.Read(paddingLen) != 0)
        {
            throw new ArgumentException("Invalid padding value, it should be all zeroes.");
        }

        List<byte> value = [];
        while (valueReader.CanRead(8))
        {
            value.Add((byte)valueReader.Read(8));
        }

        return new Share(
            id: id,
            extendable: extendable,
            iterationExponent: prefixReader.Read(ITERATION_EXP_LENGTH_BITS),
            groupIndex: prefixReader.Read(4),
            new Group(prefixReader.Read(4) + 1, prefixReader.Read(4) + 1),
            memberIndex: prefixReader.Read(4),
            memberThreshold: prefixReader.Read(4) + 1,
            value: [.. value]
        );
    }

    public string ToMnemonic()
    {
        BitStreamWriter prefixWriter = new();
        prefixWriter.Write(Id, ID_LENGTH_BITS);
        prefixWriter.Write(Extendable ? 1 : 0, EXTENDABLE_FLAG_LENGTH_BITS);
        prefixWriter.Write(IterationExponent, ITERATION_EXP_LENGTH_BITS);
        prefixWriter.Write(GroupIndex, 4);
        prefixWriter.Write(GroupThreshold - 1, 4);
        prefixWriter.Write(GroupCount - 1, 4);
        prefixWriter.Write(MemberIndex, 4);
        prefixWriter.Write(MemberThreshold - 1, 4);

        int valueWordCount = (8 * Value.Length + RADIX_BITS - 1) / RADIX_BITS;
        int padding = valueWordCount * RADIX_BITS - Value.Length * 8;
        BitStreamWriter valueWriter = new();

        valueWriter.Write(0, padding);
        foreach (byte b in Value)
        {
            valueWriter.Write(b, 8);
        }

        byte[] prefixBytes = prefixWriter.ToByteArray();
        byte[] valueBytes = valueWriter.ToByteArray();
        byte[] bytes = prefixBytes.Concat(valueBytes);
        int[] shareWords = BytesToWords(bytes);
        int[] words = shareWords.Concat([0, 0, 0]);
        int chk = Checksum(words, Extendable) ^ 1;
        int len = words.Length;
        for (int i = 0; i < 3; i++)
        {
            words[len - 3 + i] = (chk >> (RADIX_BITS * (2 - i))) & 1023;
        }

        return string.Join(" ", words.Select(i => WordList.Words[i]));
    }

    public static int GenerateId(IRandom random)
    {
        return BitConverter.ToInt32(random.GetBytes(4)) % ((1 << (ID_LENGTH_BITS + 1)) - 1);
    }

    private static int[] BytesToWords(byte[] bytes)
    {
        List<int> words = [];
        BitStreamReader reader = new(bytes);
        while (reader.CanRead(10))
        {
            words.Add(reader.Read(10));
        }

        return [.. words];
    }

    private static byte[] WordsToBytes(int[] words)
    {
        BitStreamWriter writer = new();

        foreach (int word in words)
        {
            writer.Write(word, 10);
        }

        return writer.ToByteArray();
    }

    private static readonly byte[] CustomizationStringOrig = "shamir"u8.ToArray();
    private static readonly byte[] CustomizationStringExtendable = "shamir_extendable"u8.ToArray();

    private static int Checksum(int[] values, bool extendable)
    {
        int[] gen = [
            0x00E0E040, 0x01C1C080, 0x03838100, 0x07070200, 0x0E0E0009,
            0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x03F3F120,
        ];

        int chk = 1;
        byte[] customizationString = extendable ? CustomizationStringExtendable : CustomizationStringOrig;
        foreach (int v in customizationString.Select(x => (int)x).Concat(values))
        {
            int b = chk >> 20;
            chk = ((chk & 0xFFFFF) << 10) ^ v;
            for (int i = 0; i < 10; i++)
            {
                chk ^= ((b >> i) & 1) != 0 ? gen[i] : 0;
            }
        }

        return chk;
    }
}
