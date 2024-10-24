using Slip39.Properties;

using System;
using System.Collections.Generic;
using System.Linq;

namespace Slip39;

public static class WordList
{
    public static string[] Words { get; }

    private static readonly Dictionary<string, int> _wordIndexMap;

    static WordList()
    {
        Words = LoadWordlist();
        _wordIndexMap = Words
            .Select((word, i) => (word, i ))
            .ToDictionary(t => t.word, t => t.i);
    }

    private static string[] LoadWordlist()
    {
        string[] wordlist = Resources.WordList.Split(["\r\n", "\r", "\n"], StringSplitOptions.RemoveEmptyEntries);

        return wordlist.Length == 1024
            ? wordlist
            : throw new InvalidOperationException($"The wordlist should contain 1024 words, but it contains {wordlist.Length} words.");
    }

    public static int[] MnemonicToIndices(string mnemonic)
    {
        try
        {
            return mnemonic.Split()
                           .Select(word => _wordIndexMap[word.ToLower()])
                           .ToArray();
        }
        catch (KeyNotFoundException keyError)
        {
            throw new Slip39Exception($"Invalid mnemonic word {keyError.Message}.", keyError);
        }
    }
}
