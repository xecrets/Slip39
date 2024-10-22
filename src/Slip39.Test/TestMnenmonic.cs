using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Xunit;

namespace Slip39.Test;

public class TestMnenmonic
{
    private static readonly byte[] _masterSecret = "ABCDEFGHIJKLMNOP"u8.ToArray();

    [Fact]
    public void TestGenerateMnemonics()
    {
        Share[] shares = Shamir.Generate(3, 5, _masterSecret);

    }
}
