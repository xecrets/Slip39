using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Slip39;

public class StrongRandom : IRandom
{
    private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

    public void GetBytes(byte[] buffer)
    {
        _rng.GetBytes(buffer);
    }

    public byte[] GetBytes(int count)
    {
        byte[] bytes = new byte[count];
        _rng.GetBytes(bytes);
        return bytes;
    }
}
