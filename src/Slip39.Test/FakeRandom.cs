namespace Slip39.Test;

internal class FakeRandom : IRandom
{
    private readonly System.Random _random = new System.Random(0);

    public void GetBytes(byte[] buffer)
    {
        _random.NextBytes(buffer);
    }

    public byte[] GetBytes(int count)
    {
        byte[] bytes = new byte[count];
        _random.NextBytes(bytes);
        return bytes;
    }
}
