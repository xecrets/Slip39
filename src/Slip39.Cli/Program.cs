using System.CommandLine;
using System.CommandLine.Parsing;
using System.Diagnostics;


namespace Slip39.Cli;

class Program
{
    static async Task<int> Main(string[] args)
    {
        Option<int> countOption = new(
           name: "--count",
           description: "The number of shares to generate.");

        Option<int> thresholdOption = new(
            name: "--threshold",
            description: "The number of shares required to recover the master secret.");

        Command splitCommand = new(name: "split", description: "Split the secret into shares")
        {
            countOption,
            thresholdOption,
        };

        splitCommand.SetHandler((c, t) =>
        {
            Share[] shares = Shamir.Generate((byte)t, (byte)c, "svante          "u8.ToArray());
            foreach (Share share in shares)
            {
                Console.WriteLine(share.ToMnemonic(WordList.Wordlist));
            }
        }, countOption, thresholdOption);

        Option<string[]> shareOption = new(
        name: "--share",
        description: "Combine this and any additional shares to recover the master secret.")
        {
            AllowMultipleArgumentsPerToken = true,
            IsRequired = true,
        };

        Command combineCommand = new(name: "combine", description: "Combine the given number of shares and recover the secret.")
        {
            shareOption,
        };

        combineCommand.SetHandler((sh) => { }, shareOption);

        RootCommand rootCommand = new("Simple app to generate Shamir secret shares and combine them again.")
        {
            splitCommand,
            combineCommand,
        };

        return await rootCommand.InvokeAsync(args);
    }
}