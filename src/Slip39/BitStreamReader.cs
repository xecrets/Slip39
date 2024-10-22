using System.IO;

namespace Slip39;

public class BitStreamReader(BitStream stream)
{
    public BitStreamReader(byte[] buffer)
        : this(new BitStream(buffer))
    {
    }

    public int Read(int count) =>
        stream.TryReadBits(count, out var value)
            ? value
            : throw new EndOfStreamException("There are no more bits to read.");

    public bool CanRead(int count) => stream.Available >= count;
}
