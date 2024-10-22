namespace Slip39;

class BitStreamWriter(BitStream stream)
{
    public BitStreamWriter()
        : this(new BitStream(new byte[100]))
    { }

    public void Write(long data, int count) =>
        stream.WriteBits(data, (byte)count);

    public byte[] ToByteArray() =>
        stream.ToByteArray();
}
