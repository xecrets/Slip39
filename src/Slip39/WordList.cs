using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Slip39;

public static class WordList
{
    public static readonly string[] Words;

    private static readonly Dictionary<string, int> WordIndexMap;

    static WordList()
    {
        Words = LoadWordlist();
        WordIndexMap = Words
            .Select((word, i) => new {word, i})
            .ToDictionary(x => x.word, x => x.i);
    }

    private static string[] LoadWordlist()
    {
        string wordlistPath = Path.Combine(AppContext.BaseDirectory, "wordlist.txt");
        string[] wordlist = File.ReadAllLines(wordlistPath)
                           .Select(word => word.Trim())
                           .ToArray();

        return wordlist.Length != 1024
            ? throw new InvalidOperationException(
                $"The wordlist should contain 1024 words, but it contains {wordlist.Length} words."
            )
            : wordlist;
    }

    public static int[] MnemonicToIndices(string mnemonic)
    {
        try
        {
            return mnemonic.Split()
                           .Select(word => WordIndexMap[word.ToLower()])
                           .ToArray();
        }
        catch (KeyNotFoundException keyError)
        {
            throw new MnemonicException($"Invalid mnemonic word {keyError.Message}.", keyError);
        }
    }
}

public class MnemonicException(string message, Exception innerException) : Exception(message, innerException)
{
}
